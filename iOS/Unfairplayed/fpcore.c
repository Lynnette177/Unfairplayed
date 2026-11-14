// Unfairplayed — FairPlay decryption research tool.
#include "fpcore.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <libkern/OSByteOrder.h>
#include <mach/mach.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>

#pragma mark - mremap_encrypted

typedef int (*mremap_encrypted_fn)(void *, size_t, uint32_t, uint32_t, uint32_t);

static int raw_mremap_encrypted(void *addr, size_t len, uint32_t cryptid, uint32_t cputype, uint32_t cpusubtype) {
#if defined(__arm64__)
    register uint64_t x0 __asm__("x0") = (uint64_t)addr;
    register uint64_t x1 __asm__("x1") = (uint64_t)len;
    register uint64_t x2 __asm__("x2") = cryptid;
    register uint64_t x3 __asm__("x3") = cputype;
    register uint64_t x4 __asm__("x4") = cpusubtype;
    register uint64_t x16 __asm__("x16") = 489; // SYS_mremap_encrypted
    uint64_t failed;
    __asm__ volatile("svc #0x80\n\tcset %[f], cs\n"
                     : "+r"(x0), "+r"(x1), [f] "=r"(failed)
                     : "r"(x2), "r"(x3), "r"(x4), "r"(x16)
                     : "memory", "cc");
    if (failed) { errno = (int)x0; return -1; }
    return (int)x0;
#else
    errno = ENOTSUP;
    return -1;
#endif
}

static int do_mremap_encrypted(void *addr, size_t len, uint32_t cryptid, uint32_t cputype, uint32_t cpusubtype) {
    static mremap_encrypted_fn fn;
    static int resolved;
    if (!resolved) { fn = (mremap_encrypted_fn)dlsym(RTLD_DEFAULT, "mremap_encrypted"); resolved = 1; }
    if (fn) return fn(addr, len, cryptid, cputype, cpusubtype);
    return raw_mremap_encrypted(addr, len, cryptid, cputype, cpusubtype);
}

#pragma mark - helpers

static void logf_(fp_log_t log, void *ctx, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void logf_(fp_log_t log, void *ctx, const char *fmt, ...) {
    char buf[2048];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    if (log) log(ctx, buf); else fprintf(stderr, "%s\n", buf);
}

static double now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static double entropy(const uint8_t *p, size_t n) {
    if (!n) return 0;
    uint64_t h[256] = {0};
    for (size_t i = 0; i < n; i++) h[p[i]]++;
    double e = 0;
    for (int i = 0; i < 256; i++) if (h[i]) { double q = (double)h[i] / n; e -= q * log2(q); }
    return e;
}

static uint32_t code_words(const uint8_t *p, size_t n) {
    uint32_t c = 0;
    for (size_t i = 0; i + 4 <= n; i += 4) {
        uint32_t w; memcpy(&w, p + i, 4);
        if (w == 0xd65f03c0 /* ret */ || w == 0xd503237f /* pacibsp */ || w == 0xd65f0fff /* retab */) c++;
    }
    return c;
}

static bool pread_full(int fd, void *buf, size_t n, off_t off) {
    uint8_t *p = buf;
    while (n) {
        ssize_t r = pread(fd, p, n, off);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return false; }
        p += r; n -= r; off += r;
    }
    return true;
}

static bool pwrite_full(int fd, const void *buf, size_t n, off_t off) {
    const uint8_t *p = buf;
    while (n) {
        ssize_t r = pwrite(fd, p, n, off);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return false; }
        p += r; n -= r; off += r;
    }
    return true;
}

const char *fp_mode_name(int mode) {
    switch (mode) {
        case FP_MODE_R_CID2:  return "R/cryptid2";
        case FP_MODE_RX_CID1: return "RX/cryptid1";
        case FP_MODE_R_CID1:  return "R/cryptid1";
    }
    return "?";
}

bool fp_is_macho(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    uint32_t m = 0;
    bool ok = pread(fd, &m, 4, 0) == 4;
    close(fd);
    if (!ok) return false;
    return m == MH_MAGIC_64 || m == MH_MAGIC || m == FAT_CIGAM || m == FAT_CIGAM_64;
}

#pragma mark - parsing

static int parse_thin(int fd, uint64_t off, uint64_t size, fp_slice_t *s, char *err, size_t errlen) {
    struct mach_header_64 mh;
    if (!pread_full(fd, &mh, sizeof mh, off)) { snprintf(err, errlen, "short read (header)"); return -1; }
    if (mh.magic != MH_MAGIC_64) { snprintf(err, errlen, "unsupported magic 0x%x", mh.magic); return -1; }
    memset(s, 0, sizeof *s);
    s->slice_off = off; s->slice_size = size;
    s->cputype = mh.cputype; s->cpusubtype = mh.cpusubtype; s->filetype = mh.filetype;
    if (mh.sizeofcmds > 16 * 1024 * 1024) { snprintf(err, errlen, "sizeofcmds too large"); return -1; }
    uint8_t *cmds = malloc(mh.sizeofcmds);
    if (!cmds || !pread_full(fd, cmds, mh.sizeofcmds, off + sizeof mh)) { free(cmds); snprintf(err, errlen, "short read (cmds)"); return -1; }
    uint32_t pos = 0;
    for (uint32_t i = 0; i < mh.ncmds && pos + 8 <= mh.sizeofcmds; i++) {
        struct load_command *lc = (struct load_command *)(cmds + pos);
        if (lc->cmdsize < 8 || pos + lc->cmdsize > mh.sizeofcmds) break;
        if (lc->cmd == LC_ENCRYPTION_INFO_64 || lc->cmd == LC_ENCRYPTION_INFO) {
            struct encryption_info_command *e = (void *)lc;
            s->has_enc = true;
            s->enc_lc_off = off + sizeof mh + pos;
            s->cryptoff = e->cryptoff; s->cryptsize = e->cryptsize; s->cryptid = e->cryptid;
        } else if (lc->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *l = (void *)lc;
            s->cs_off = l->dataoff; s->cs_size = l->datasize;
        }
        pos += lc->cmdsize;
    }
    free(cmds);
    return 0;
}

int fp_parse(const char *path, fp_slice_t *slices, int max, int *count, char *err, size_t errlen) {
    *count = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) { snprintf(err, errlen, "open: %s", strerror(errno)); return -1; }
    struct stat st; fstat(fd, &st);
    uint32_t magic = 0;
    if (!pread_full(fd, &magic, 4, 0)) { close(fd); snprintf(err, errlen, "short read"); return -1; }
    int rc = 0;
    if (magic == FAT_CIGAM || magic == FAT_CIGAM_64) {
        bool is64 = magic == FAT_CIGAM_64;
        struct fat_header fh; pread_full(fd, &fh, sizeof fh, 0);
        uint32_t n = OSSwapBigToHostInt32(fh.nfat_arch);
        uint64_t p = sizeof fh;
        for (uint32_t i = 0; i < n && *count < max; i++) {
            uint64_t o, sz; uint32_t ct;
            if (is64) {
                struct fat_arch_64 fa; if (!pread_full(fd, &fa, sizeof fa, p)) break; p += sizeof fa;
                o = OSSwapBigToHostInt64(fa.offset); sz = OSSwapBigToHostInt64(fa.size); ct = OSSwapBigToHostInt32(fa.cputype);
            } else {
                struct fat_arch fa; if (!pread_full(fd, &fa, sizeof fa, p)) break; p += sizeof fa;
                o = OSSwapBigToHostInt32(fa.offset); sz = OSSwapBigToHostInt32(fa.size); ct = OSSwapBigToHostInt32(fa.cputype);
            }
            if (!(ct & CPU_ARCH_ABI64)) continue; // 32-bit slices are irrelevant on arm64-only devices
            char e2[128];
            if (parse_thin(fd, o, sz, &slices[*count], e2, sizeof e2) == 0) (*count)++;
        }
    } else if (magic == MH_MAGIC_64) {
        rc = parse_thin(fd, 0, (uint64_t)st.st_size, &slices[0], err, errlen);
        if (rc == 0) *count = 1;
    } else {
        snprintf(err, errlen, "not a 64-bit Mach-O (magic 0x%08x)", magic);
        rc = -1;
    }
    close(fd);
    return rc;
}

#pragma mark - data-only encrypted regions

// Some CocoaPods dummy frameworks have a zero-length __text. Their encrypted
// range contains constants, C strings and zero padding, so RET counting cannot
// validate them. Keep this fallback narrow and reject zero-filled read failures.
static bool data_only_plaintext_valid(int fd, const fp_slice_t *s, const uint8_t *plain) {
    if (!s->cryptsize || s->cryptsize > 1024 * 1024 || !plain) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0 || s->slice_off > (uint64_t)st.st_size ||
        s->slice_size > (uint64_t)st.st_size - s->slice_off ||
        s->cryptoff > s->slice_size || s->cryptsize > s->slice_size - s->cryptoff) return false;
    struct mach_header_64 mh;
    if (!pread_full(fd, &mh, sizeof mh, s->slice_off) || mh.magic != MH_MAGIC_64 ||
        s->slice_size < sizeof mh || mh.sizeofcmds > 16 * 1024 * 1024 ||
        mh.sizeofcmds > s->slice_size - sizeof mh) return false;
    uint8_t *commands = malloc(mh.sizeofcmds);
    uint8_t *covered = calloc(s->cryptsize, 1);
    if (!commands || !covered || !pread_full(fd, commands, mh.sizeofcmds, s->slice_off + sizeof mh)) {
        free(commands); free(covered); return false;
    }
    const uint64_t begin = s->cryptoff, end = begin + s->cryptsize;
    uint64_t sections = 0, strings = 0;
    uint32_t pos = 0;
    bool valid = true;
    for (uint32_t i = 0; i < mh.ncmds && valid; i++) {
        if (pos > mh.sizeofcmds || mh.sizeofcmds - pos < sizeof(struct load_command)) { valid = false; break; }
        const struct load_command *lc = (const void *)(commands + pos);
        if (lc->cmdsize < sizeof *lc || lc->cmdsize > mh.sizeofcmds - pos) { valid = false; break; }
        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64)) { valid = false; break; }
            const struct segment_command_64 *segment = (const void *)lc;
            if (segment->nsects > (lc->cmdsize - sizeof *segment) / sizeof(struct section_64)) { valid = false; break; }
            const struct section_64 *section = (const void *)(segment + 1);
            for (uint32_t j = 0; j < segment->nsects && valid; j++) {
                const struct section_64 *v = &section[j];
                uint32_t type = v->flags & SECTION_TYPE;
                if (!v->size || type == S_ZEROFILL || type == S_GB_ZEROFILL || type == S_THREAD_LOCAL_ZEROFILL) continue;
                uint64_t start = v->offset;
                if (start > s->slice_size || v->size > s->slice_size - start) { valid = false; break; }
                uint64_t stop = start + v->size;
                if (stop <= begin || start >= end) continue;
                if ((v->flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)) ||
                    !strncmp(v->sectname, "__text", 16) || !strncmp(v->sectname, "__stubs", 16) ||
                    !strncmp(v->sectname, "__stub_helper", 16) || !strncmp(v->sectname, "__auth_stubs", 16) ||
                    start < begin || stop > end) { valid = false; break; }
                sections++;
                const uint8_t *bytes = plain + start - begin;
                if (type == S_CSTRING_LITERALS) {
                    bool has_text = false;
                    if (bytes[v->size - 1] != 0) { valid = false; break; }
                    for (uint64_t k = 0; k < v->size; k++) {
                        uint8_t c = bytes[k];
                        if (c && (c < 0x20 || c > 0x7e)) { valid = false; break; }
                        if (c) has_text = true;
                    }
                    if (has_text) strings++;
                }
                for (uint64_t k = start - begin; k < stop - begin && valid; k++) {
                    if (covered[k]) valid = false;
                    covered[k] = 1;
                }
            }
        }
        pos += lc->cmdsize;
    }
    if (pos != mh.sizeofcmds || !sections || !strings) valid = false;
    for (uint64_t k = 0; k < s->cryptsize && valid; k++) {
        if (!covered[k] && plain[k] != 0) valid = false;
    }
    free(commands); free(covered);
    return valid;
}

#pragma mark - attempt


// A small function may return by tail-calling an imported routine (for example
// objc_autoreleaseReturnValue) and contain no RET at all. Recognize a bounded
// stack-restoring epilogue followed by a branch to a real arm64 import stub.
// This is checked only against the successfully read, remapped bytes.
static bool tail_call_plaintext_valid(int fd, const fp_slice_t *s, const uint8_t *plain) {
    if (!plain || !s->cryptsize || s->cryptsize > 1024 * 1024 ||
        s->cryptoff > s->slice_size || s->cryptsize > s->slice_size - s->cryptoff) return false;
    struct mach_header_64 mh;
    if (s->slice_size < sizeof mh || !pread_full(fd, &mh, sizeof mh, s->slice_off) ||
        mh.magic != MH_MAGIC_64 || mh.cputype != CPU_TYPE_ARM64 ||
        mh.sizeofcmds > 16 * 1024 * 1024 || mh.sizeofcmds > s->slice_size - sizeof mh) return false;
    uint8_t *commands = malloc(mh.sizeofcmds);
    if (!commands || !pread_full(fd, commands, mh.sizeofcmds, s->slice_off + sizeof mh)) {
        free(commands); return false;
    }
    struct section_64 text = {0}, stubs = {0}, pointers[32];
    uint32_t pointer_count = 0;
    uint32_t pos = 0; bool valid = true;
    for (uint32_t i = 0; i < mh.ncmds && valid; i++) {
        if (pos > mh.sizeofcmds || mh.sizeofcmds - pos < sizeof(struct load_command)) { valid = false; break; }
        const struct load_command *lc = (const void *)(commands + pos);
        if (lc->cmdsize < sizeof *lc || lc->cmdsize > mh.sizeofcmds - pos) { valid = false; break; }
        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64)) { valid = false; break; }
            const struct segment_command_64 *segment = (const void *)lc;
            if (segment->nsects > (lc->cmdsize - sizeof *segment) / sizeof(struct section_64)) { valid = false; break; }
            const struct section_64 *sections = (const void *)(segment + 1);
            for (uint32_t j = 0; j < segment->nsects; j++) {
                const struct section_64 *v = &sections[j];
                uint32_t type = v->flags & SECTION_TYPE;
                if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS) {
                    if (pointer_count == 32 || v->offset > s->slice_size || v->size > s->slice_size - v->offset ||
                        v->addr > UINT64_MAX - v->size) { valid = false; break; }
                    pointers[pointer_count++] = *v;
                }
                if (strncmp(v->segname, "__TEXT", 16) || strncmp(segment->segname, "__TEXT", 16)) continue;
                if (!strncmp(v->sectname, "__text", 16)) {
                    if (text.size) { valid = false; break; }
                    text = *v;
                } else if (!strncmp(v->sectname, "__stubs", 16)) {
                    if (stubs.size) { valid = false; break; }
                    stubs = *v;
                }
            }
        }
        pos += lc->cmdsize;
    }
    free(commands);
    uint64_t end = (uint64_t)s->cryptoff + s->cryptsize;
    if (!valid || pos != mh.sizeofcmds || text.size < 12 || stubs.size < 12 ||
        (text.flags & SECTION_TYPE) != S_REGULAR || !(text.flags & S_ATTR_PURE_INSTRUCTIONS) ||
        (stubs.flags & SECTION_TYPE) != S_SYMBOL_STUBS || stubs.reserved2 != 12 ||
        text.offset < s->cryptoff || text.offset > end || text.size > end - text.offset ||
        stubs.offset < s->cryptoff || stubs.offset > end || stubs.size > end - stubs.offset ||
        text.offset % 4 || text.size % 4 || stubs.offset % 4 || stubs.size % 12 ||
        text.addr > UINT64_MAX - text.size || stubs.addr > UINT64_MAX - stubs.size ||
        !(text.offset + text.size <= stubs.offset || stubs.offset + stubs.size <= text.offset) ||
        !(text.addr + text.size <= stubs.addr || stubs.addr + stubs.size <= text.addr)) return false;
    const uint8_t *code = plain + text.offset - s->cryptoff;
    for (uint64_t offset = 8; offset < text.size; offset += 4) {
        uint32_t branch, add;
        memcpy(&branch, code + offset, 4); memcpy(&add, code + offset - 4, 4);
        if ((branch & 0xfc000000) != 0x14000000 || // B, not BL
            (add & 0xffc003ff) != 0x910003ff) continue; // ADD SP, SP, #imm (unshifted)
        uint32_t stack = (add >> 10) & 0xfff;
        if (!stack || stack > 1024 || stack % 16) continue;
        int64_t displacement = (int64_t)(branch & 0x03ffffff);
        if (displacement & 0x02000000) displacement -= 0x04000000;
        displacement *= 4;
        uint64_t pc = text.addr + offset;
        if ((displacement < 0 && pc < (uint64_t)-displacement) ||
            (displacement >= 0 && pc > UINT64_MAX - (uint64_t)displacement)) continue;
        uint64_t target = displacement < 0 ? pc - (uint64_t)-displacement : pc + (uint64_t)displacement;
        if (target < stubs.addr || target - stubs.addr > stubs.size - 12 || (target - stubs.addr) % 12) continue;
        const uint8_t *stub = plain + stubs.offset - s->cryptoff + target - stubs.addr;
        uint32_t adrp, ldr, br;
        memcpy(&adrp, stub, 4); memcpy(&ldr, stub + 4, 4); memcpy(&br, stub + 8, 4);
        if (br != 0xd61f0200) continue; // BR X16
        uint64_t pointer_pc; int64_t pointer_delta;
        if ((adrp & 0x9f00001f) == 0x90000010 && (ldr & 0xffc003ff) == 0xf9400210) {
            // ADRP X16; LDR X16, [X16, #imm]; BR X16.
            pointer_pc = target & ~UINT64_C(4095);
            pointer_delta = ((int64_t)((adrp >> 5) & 0x7ffff) << 2) | ((adrp >> 29) & 3);
            if (pointer_delta & 0x100000) pointer_delta -= 0x200000;
            pointer_delta = pointer_delta * 4096 + ((ldr >> 10) & 0xfff) * 8;
        } else if (adrp == 0xd503201f && (ldr & 0xff00001f) == 0x58000010) {
            // Linker-relaxed stub: NOP; LDR X16, literal; BR X16.
            if (target > UINT64_MAX - 4) continue;
            pointer_pc = target + 4;
            pointer_delta = (ldr >> 5) & 0x7ffff;
            if (pointer_delta & 0x40000) pointer_delta -= 0x80000;
            pointer_delta *= 4;
        } else continue;
        if ((pointer_delta < 0 && pointer_pc < (uint64_t)-pointer_delta) ||
            (pointer_delta >= 0 && pointer_pc > UINT64_MAX - (uint64_t)pointer_delta)) continue;
        uint64_t pointer = pointer_delta < 0 ? pointer_pc - (uint64_t)-pointer_delta : pointer_pc + (uint64_t)pointer_delta;
        bool imported_pointer = false;
        for (uint32_t i = 0; i < pointer_count; i++) {
            const struct section_64 *v = &pointers[i];
            if (v->size >= 8 && pointer >= v->addr && pointer - v->addr <= v->size - 8 &&
                pointer % 8 == 0 && (pointer - v->addr) % 8 == 0) imported_pointer = true;
        }
        if (!imported_pointer) continue;
        uint8_t restored[128] = {0};
        for (uint64_t distance = 8; distance <= 48 && distance <= offset; distance += 4) {
            uint32_t word; memcpy(&word, code + offset - distance, 4);
            bool gp = (word & 0xffc003e0) == 0xa94003e0; // LDP Xt, Xt2, [SP, #offset]
            bool fp = (word & 0xffc003e0) == 0x6d4003e0; // LDP Dt, Dt2, [SP, #offset]
            uint32_t r1 = word & 31, r2 = (word >> 10) & 31, slot = (word >> 15) & 127;
            if ((!gp && !fp) || (slot & 64) || slot * 8 + 16 > stack ||
                restored[slot] || restored[slot + 1] || r1 == r2) break;
            restored[slot] = restored[slot + 1] = 1;
            if (gp && r1 == 29 && r2 == 30) return true;
            if (gp ? (r1 < 19 || r1 > 28 || r2 < 19 || r2 > 28) :
                     (r1 < 8 || r1 > 15 || r2 < 8 || r2 > 15)) break;
        }
    }
    return false;
}

int fp_attempt(const char *path, const fp_slice_t *s, int mode, bool addsigs, uint8_t *out, fp_attempt_t *res) {
    memset(res, 0, sizeof *res);
    res->mode = mode; res->addsigs = addsigs; res->mremap_ret = -1;
    double t0 = now_ms();
    const uint64_t pg = (uint64_t)getpagesize();
    if (!s->has_enc || s->cryptsize == 0) return -1;
    if (s->slice_off % pg) { res->mmap_errno = EINVAL; return -1; }
    if (s->cryptoff % pg) { res->mremap_errno = EINVAL; return -1; }

    int fd = open(path, O_RDONLY);
    if (fd < 0) { res->mmap_errno = errno; return -1; }

    if (addsigs && s->cs_size) {
        fsignatures_t fs = { .fs_file_start = (off_t)s->slice_off, .fs_blob_start = (void *)(uintptr_t)s->cs_off, .fs_blob_size = s->cs_size };
        if (fcntl(fd, F_ADDFILESIGS_RETURN, &fs) == -1) res->sig_errno = errno;
    }

    uint64_t map_len = ((uint64_t)s->cryptoff + s->cryptsize + pg - 1) & ~(pg - 1);
    int prot = PROT_READ | (mode == FP_MODE_RX_CID1 ? PROT_EXEC : 0);
    uint8_t *base = mmap(NULL, map_len, prot, MAP_PRIVATE, fd, (off_t)s->slice_off);
    if (base == MAP_FAILED) { res->mmap_errno = errno; close(fd); res->ms = now_ms() - t0; return -1; }

    uint8_t *orig = malloc(s->cryptsize);
    uint8_t *dec = out ? out : malloc(s->cryptsize);
    if (!orig || !dec || !pread_full(fd, orig, s->cryptsize, (off_t)(s->slice_off + s->cryptoff))) {
        free(orig); if (!out) free(dec); munmap(base, map_len); close(fd); res->mmap_errno = EIO; return -1;
    }

    uint32_t cid = (mode == FP_MODE_R_CID2) ? 2 : 1;
    errno = 0;
    res->mremap_ret = do_mremap_encrypted(base + s->cryptoff, s->cryptsize, cid, s->cputype, s->cpusubtype);
    res->mremap_errno = res->mremap_ret == 0 ? 0 : errno;

    res->ret_before = code_words(orig, s->cryptsize);
    res->ent_before = entropy(orig, s->cryptsize);
    if (res->mremap_ret == 0) {
        // Read through the remapped range with vm_read_overwrite so that a failing
        // page-in (decrypt error) is reported as a kern_return_t instead of SIGBUS.
        uint64_t total = (s->cryptsize + pg - 1) / pg;
        res->pages_total = total;
        for (uint64_t i = 0; i < total; i++) {
            uint64_t off = i * pg;
            uint64_t n = (off + pg <= s->cryptsize) ? pg : (s->cryptsize - off);
            vm_size_t got = 0;
            kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)(base + s->cryptoff + off), (vm_size_t)n,
                                                 (vm_address_t)(dec + off), &got);
            if (kr == KERN_SUCCESS && got == n) {
                res->pages_ok++;
            } else {
                if (!res->first_fail_kr) { res->first_fail_kr = kr ? kr : -1; res->first_fail_off = s->cryptoff + off; }
                memset(dec + off, 0, n);
            }
        }
        res->changed = memcmp(orig, dec, s->cryptsize) != 0;
        res->ret_after = code_words(dec, s->cryptsize);
        res->ent_after = entropy(dec, s->cryptsize);
        if (res->pages_ok == res->pages_total && res->changed &&
            res->ret_after <= res->ret_before && res->ent_after < 7.5) {
            res->data_only_layout = data_only_plaintext_valid(fd, s, dec);
            res->tail_call_layout = tail_call_plaintext_valid(fd, s, dec);
        }
    }
    free(orig);
    if (!out) free(dec);
    munmap(base, map_len);
    close(fd);
    res->ms = now_ms() - t0;
    return (res->mremap_ret == 0 && res->pages_ok == res->pages_total && res->changed) ? 0 : -1;
}

void fp_attempt_describe(const fp_attempt_t *a, char *buf, size_t len) {
    snprintf(buf, len,
             "%s%s: sig=%s mmap=%s mremap=%d(errno %d %s) pages=%llu/%llu firstfail=kr%d@0x%llx changed=%d "
             "code-words %u->%u entropy %.3f->%.3f data-only=%d tail-call=%d (%.0f ms)",
             fp_mode_name(a->mode), a->addsigs ? "+sigs" : "",
             a->addsigs ? (a->sig_errno ? strerror(a->sig_errno) : "ok") : "-",
             a->mmap_errno ? strerror(a->mmap_errno) : "ok",
             a->mremap_ret, a->mremap_errno, a->mremap_errno ? strerror(a->mremap_errno) : "ok",
             (unsigned long long)a->pages_ok, (unsigned long long)a->pages_total,
             a->first_fail_kr, (unsigned long long)a->first_fail_off, a->changed,
             a->ret_before, a->ret_after, a->ent_before, a->ent_after, a->data_only_layout, a->tail_call_layout, a->ms);
}

static bool attempt_looks_decrypted(const fp_attempt_t *a) {
    // Instruction counting is a heuristic, not a requirement for data-only text.
    // Both branches still require successful remapping, complete reads and a
    // changed low-entropy result; the fallbacks additionally validate data layout
    // or a stack-restoring tail call into an import stub.
    return a->mremap_ret == 0 && a->pages_total > 0 && a->pages_ok == a->pages_total && a->changed &&
           a->ent_before > 7.9 && a->ent_after < 7.5 &&
           (a->ret_after > a->ret_before || a->data_only_layout || a->tail_call_layout);
}

int fp_probe_file(const char *path, const int *modes, int nmodes, fp_log_t log, void *ctx) {
    fp_slice_t sl[FP_MAX_SLICES]; int n = 0; char err[256] = {0};
    if (fp_parse(path, sl, FP_MAX_SLICES, &n, err, sizeof err) != 0) { logf_(log, ctx, "  parse failed: %s", err); return -1; }
    int successes = 0;
    for (int i = 0; i < n; i++) {
        const fp_slice_t *s = &sl[i];
        logf_(log, ctx, "  slice[%d] cpu=0x%x/0x%x type=%u off=0x%llx enc=%d cryptoff=0x%x cryptsize=0x%x cryptid=%u cs=0x%x+0x%x",
              i, s->cputype, s->cpusubtype, s->filetype, (unsigned long long)s->slice_off, s->has_enc,
              s->cryptoff, s->cryptsize, s->cryptid, s->cs_off, s->cs_size);
        if (!s->has_enc || s->cryptid == 0) continue;
        for (int m = 0; m < nmodes; m++) {
            for (int sig = 0; sig < 2; sig++) {
                fp_attempt_t a; char d[512];
                fp_attempt(path, s, modes[m], sig, NULL, &a);
                fp_attempt_describe(&a, d, sizeof d);
                bool ok = attempt_looks_decrypted(&a);
                if (ok) successes++;
                logf_(log, ctx, "    %s %s", ok ? "[DECRYPTED]" : "[--]", d);
            }
        }
    }
    return successes;
}

#pragma mark - decrypt to file

static int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    struct stat st; fstat(in, &st);
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, (st.st_mode & 0777) | 0600);
    if (out < 0) { close(in); return -1; }
    uint8_t *buf = malloc(1 << 20);
    ssize_t r; int rc = 0;
    while ((r = read(in, buf, 1 << 20)) > 0) if (write(out, buf, (size_t)r) != r) { rc = -1; break; }
    if (r < 0) rc = -1;
    free(buf); close(in); close(out);
    return rc;
}


// 32-bit iOS slices are not executed on supported devices and are deliberately
// not passed to the arm64 decryptor. Remove them from the exported copy so they
// cannot remain as encrypted architectures in an otherwise successful IPA.
static int drop_32bit_slices(const char *path, fp_log_t log, void *ctx) {
    int fd=open(path,O_RDWR); if(fd<0) return -1;
    uint32_t magic=0; struct stat st;
    if(fstat(fd,&st)!=0 || !pread_full(fd,&magic,4,0)) { close(fd); return -1; }
    if(magic!=FAT_CIGAM && magic!=FAT_CIGAM_64) { close(fd); return 0; }
    bool wide=magic==FAT_CIGAM_64; struct fat_header header;
    if(!pread_full(fd,&header,sizeof header,0)) { close(fd); return -1; }
    uint32_t count=OSSwapBigToHostInt32(header.nfat_arch);
    size_t entry_size=wide?sizeof(struct fat_arch_64):sizeof(struct fat_arch);
    if(!count || count>FP_MAX_SLICES || st.st_size<0 ||
       sizeof header+(uint64_t)count*entry_size>(uint64_t)st.st_size) { close(fd); return -1; }
    uint8_t entries[FP_MAX_SLICES*sizeof(struct fat_arch_64)]={0};
    if(!pread_full(fd,entries,count*entry_size,sizeof header)) { close(fd); return -1; }
    uint32_t kept=0; uint64_t first_offset=0,first_size=0;
    for(uint32_t i=0;i<count;i++) {
        uint8_t *entry=entries+i*entry_size; uint32_t cpu; uint64_t offset,size;
        if(wide) { struct fat_arch_64 v; memcpy(&v,entry,sizeof v); cpu=OSSwapBigToHostInt32(v.cputype);offset=OSSwapBigToHostInt64(v.offset);size=OSSwapBigToHostInt64(v.size); }
        else { struct fat_arch v; memcpy(&v,entry,sizeof v);cpu=OSSwapBigToHostInt32(v.cputype);offset=OSSwapBigToHostInt32(v.offset);size=OSSwapBigToHostInt32(v.size); }
        if(offset<sizeof header+(uint64_t)count*entry_size || offset>(uint64_t)st.st_size ||
           !size || size>(uint64_t)st.st_size-offset) { close(fd); return -1; }
        if(!(cpu&CPU_ARCH_ABI64)) continue;
        struct mach_header_64 mh;
        if(size<sizeof mh || !pread_full(fd,&mh,sizeof mh,offset) || mh.magic!=MH_MAGIC_64 ||
           (uint32_t)mh.cputype!=cpu) { close(fd);return -1; }
        if(!kept) { first_offset=offset;first_size=size; }
        memmove(entries+kept*entry_size,entry,entry_size); kept++;
    }
    if(kept==count) { close(fd);return 0; }
    if(!kept) { close(fd);return -1; }
    int rc=0;
    if(kept==1) {
        uint8_t *buffer=malloc(65536); if(!buffer) { close(fd);return -1; }
        for(uint64_t offset=0;offset<first_size && !rc;) {
            size_t amount=first_size-offset>65536?65536:(size_t)(first_size-offset);
            if(!pread_full(fd,buffer,amount,first_offset+offset) || !pwrite_full(fd,buffer,amount,offset)) rc=-1;
            offset+=amount;
        }
        free(buffer);
        if(!rc && ftruncate(fd,(off_t)first_size)!=0) rc=-1;
    } else {
        // Retain the offsets and alignment of all 64-bit slices, including arm64e.
        memset(entries+kept*entry_size,0,(count-kept)*entry_size);
        header.nfat_arch=OSSwapHostToBigInt32(kept);
        if(!pwrite_full(fd,entries,count*entry_size,sizeof header) || !pwrite_full(fd,&header,sizeof header,0)) rc=-1;
    }
    close(fd);
    if(!rc) logf_(log,ctx,"  [ARCH] removed %u unsupported 32-bit slice(s); retained %u 64-bit slice(s)",count-kept,kept);
    return rc;
}

int fp_decrypt_file(const char *in_path, const char *out_path, fp_log_t log, void *ctx) {
    fp_slice_t sl[FP_MAX_SLICES]; int n = 0; char err[256] = {0};
    if (fp_parse(in_path, sl, FP_MAX_SLICES, &n, err, sizeof err) != 0) { logf_(log, ctx, "  parse failed: %s", err); return -1; }
    bool any = false;
    for (int i = 0; i < n; i++) if (sl[i].has_enc && sl[i].cryptid) any = true;
    if (strcmp(in_path, out_path) != 0 && copy_file(in_path, out_path) != 0) { logf_(log, ctx, "  copy failed: %s", strerror(errno)); return -1; }
    if (!any) return drop_32bit_slices(out_path, log, ctx) == 0 ? 1 : -1;

    int out = open(out_path, O_RDWR);
    if (out < 0) { logf_(log, ctx, "  open out: %s", strerror(errno)); return -1; }
    const int order[][2] = { {FP_MODE_R_CID2, 0}, {FP_MODE_R_CID2, 1}, {FP_MODE_RX_CID1, 0}, {FP_MODE_RX_CID1, 1} };
    int rc = 0;
    for (int i = 0; i < n && rc == 0; i++) {
        const fp_slice_t *s = &sl[i];
        if (!s->has_enc || s->cryptid == 0) continue;
        uint8_t *dec = malloc(s->cryptsize);
        bool done = false;
        for (size_t k = 0; k < sizeof order / sizeof order[0] && !done; k++) {
            fp_attempt_t a; char d[512];
            fp_attempt(in_path, s, order[k][0], order[k][1], dec, &a);
            fp_attempt_describe(&a, d, sizeof d);
            done = attempt_looks_decrypted(&a);
            logf_(log, ctx, "  slice[%d] %s %s", i, done ? "[DECRYPTED]" : "[--]", d);
        }
        if (!done) { rc = -1; free(dec); break; }
        uint32_t zero = 0;
        if (!pwrite_full(out, dec, s->cryptsize, (off_t)(s->slice_off + s->cryptoff)) ||
            !pwrite_full(out, &zero, 4, (off_t)(s->enc_lc_off + offsetof(struct encryption_info_command, cryptid)))) {
            logf_(log, ctx, "  write failed: %s", strerror(errno)); rc = -1;
        }
        free(dec);
    }
    close(out);
    if (rc == 0 && drop_32bit_slices(out_path, log, ctx) != 0) {
        logf_(log, ctx, "  removing unsupported 32-bit slices failed"); rc = -1;
    }
    return rc;
}
