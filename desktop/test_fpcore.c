// Native regression for data-only encrypted ranges. Never calls mremap_encrypted.
#include <assert.h>
#include "../iOS/Unfairplayed/fpcore.c"

static void save_fixture(int fd, const void *bytes, size_t length) {
    assert(pwrite_full(fd, bytes, length, 0));
}

int main(void) {
    const size_t length = 0x8000, start = 0x4000, amount = 0x4000;
    uint8_t *image = calloc(length, 1), *plain = calloc(amount, 1);
    assert(image && plain);
    struct mach_header_64 *mh = (void *)image;
    *mh = (struct mach_header_64){.magic=MH_MAGIC_64, .cputype=CPU_TYPE_ARM64, .filetype=MH_DYLIB, .ncmds=2};
    struct segment_command_64 *seg = (void *)(mh + 1);
    seg->cmd=LC_SEGMENT_64; seg->cmdsize=sizeof *seg + 3 * sizeof(struct section_64);
    memcpy(seg->segname, "__TEXT", 6); seg->filesize=length; seg->vmsize=length; seg->nsects=3;
    struct section_64 *sections = (void *)(seg + 1);
    memcpy(sections[0].sectname, "__text", 6); sections[0].offset=start;
    sections[0].flags=S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
    memcpy(sections[1].sectname, "__const", 7); sections[1].offset=start; sections[1].size=64;
    memcpy(sections[2].sectname, "__objc_classname", 16); sections[2].offset=start+64;
    sections[2].size=32; sections[2].flags=S_CSTRING_LITERALS;
    struct encryption_info_command_64 *enc = (void *)((uint8_t *)seg + seg->cmdsize);
    *enc=(struct encryption_info_command_64){.cmd=LC_ENCRYPTION_INFO_64, .cmdsize=sizeof *enc, .cryptoff=start, .cryptsize=amount, .cryptid=1};
    mh->sizeofcmds=seg->cmdsize + sizeof *enc;
    uint32_t rng=12345;
    for (size_t i=start; i<length; i++) { rng ^= rng<<13; rng ^= rng>>17; rng ^= rng<<5; image[i]=(uint8_t)rng; }
    memcpy(plain, "FirebaseCoreExtension", 21);
    memcpy(plain+64, "PodsDummy_FirebaseCoreExtension", 31);
    char file[]="/tmp/unfairplayed-core-test.XXXXXX";
    int fd=mkstemp(file); assert(fd>=0); assert(ftruncate(fd,length)==0); save_fixture(fd,image,length);
    fp_slice_t s; int count=0; char error[128]={0};
    assert(fp_parse(file,&s,1,&count,error,sizeof error)==0 && count==1);
    assert(data_only_plaintext_valid(fd,&s,plain));
    assert(code_words(plain,amount)==0);

    uint8_t *zeros=calloc(amount,1); assert(zeros);
    assert(!data_only_plaintext_valid(fd,&s,zeros)); free(zeros);
    plain[amount-1]=1; assert(!data_only_plaintext_valid(fd,&s,plain)); plain[amount-1]=0;
    plain[95]='x'; assert(!data_only_plaintext_valid(fd,&s,plain)); plain[95]=0;
    plain[64]=0x81; assert(!data_only_plaintext_valid(fd,&s,plain)); plain[64]='P';
    sections[0].size=4; save_fixture(fd,image,length);
    assert(!data_only_plaintext_valid(fd,&s,plain)); sections[0].size=0;
    sections[2].flags=S_REGULAR; save_fixture(fd,image,length);
    assert(!data_only_plaintext_valid(fd,&s,plain)); sections[2].flags=S_CSTRING_LITERALS;
    seg->nsects=99; save_fixture(fd,image,length);
    assert(!data_only_plaintext_valid(fd,&s,plain)); seg->nsects=3;
    sections[2].offset=start-1; save_fixture(fd,image,length);
    assert(!data_only_plaintext_valid(fd,&s,plain)); sections[2].offset=start+64;
    save_fixture(fd,image,length); assert(data_only_plaintext_valid(fd,&s,plain));
    fp_attempt_t a={.mremap_ret=0,.pages_total=1,.pages_ok=1,.changed=true,.ent_before=7.99,.ent_after=0.071,.data_only_layout=true};
    assert(attempt_looks_decrypted(&a));
    a.data_only_layout=false; assert(!attempt_looks_decrypted(&a));
    a.ret_after=1; assert(attempt_looks_decrypted(&a));
    a.pages_ok=0; assert(!attempt_looks_decrypted(&a)); a.pages_ok=1;
    a.mremap_ret=-1; assert(!attempt_looks_decrypted(&a)); a.mremap_ret=0;
    a.changed=false; assert(!attempt_looks_decrypted(&a)); a.changed=true;
    a.ent_after=8.0; assert(!attempt_looks_decrypted(&a));
    close(fd); unlink(file); free(image); free(plain);
    puts("Data-only layout and incomplete/zero-page rejection checks passed");
    return 0;
}
