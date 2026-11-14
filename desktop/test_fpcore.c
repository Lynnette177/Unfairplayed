// Native regression for data-only encrypted ranges. Never calls mremap_encrypted.
#include <assert.h>
#include "../iOS/Unfairplayed/fpcore.c"

static void save_fixture(int fd, const void *bytes, size_t length) {
    assert(pwrite_full(fd, bytes, length, 0));
}


static void test_tail_call_without_ret(void) {
    const size_t length=0xc000, start=0x4000, amount=0x4000;
    uint8_t *image=calloc(length,1), *plain=calloc(amount,1); assert(image && plain);
    struct mach_header_64 *mh=(void *)image;
    *mh=(struct mach_header_64){.magic=MH_MAGIC_64,.cputype=CPU_TYPE_ARM64,.filetype=MH_DYLIB,.ncmds=3};
    struct segment_command_64 *text=(void *)(mh+1);
    text->cmd=LC_SEGMENT_64; text->cmdsize=sizeof *text+2*sizeof(struct section_64); text->nsects=2;
    memcpy(text->segname,"__TEXT",6);
    struct section_64 *sections=(void *)(text+1);
    memcpy(sections[0].sectname,"__text",6); memcpy(sections[0].segname,"__TEXT",6);
    sections[0].offset=start; sections[0].addr=start; sections[0].size=12; sections[0].flags=S_ATTR_PURE_INSTRUCTIONS;
    memcpy(sections[1].sectname,"__stubs",7); memcpy(sections[1].segname,"__TEXT",6);
    sections[1].offset=start+0x40; sections[1].addr=start+0x40; sections[1].size=12;
    sections[1].flags=S_SYMBOL_STUBS|S_ATTR_PURE_INSTRUCTIONS; sections[1].reserved2=12;
    struct segment_command_64 *data=(void *)((uint8_t *)text+text->cmdsize);
    data->cmd=LC_SEGMENT_64; data->cmdsize=sizeof *data+sizeof(struct section_64); data->nsects=1;
    memcpy(data->segname,"__DATA",6); struct section_64 *pointer=(void *)(data+1);
    memcpy(pointer->sectname,"__la_symbol_ptr",15); memcpy(pointer->segname,"__DATA",6);
    pointer->offset=0x8000; pointer->addr=0x8000; pointer->size=8; pointer->flags=S_LAZY_SYMBOL_POINTERS;
    struct encryption_info_command_64 *enc=(void *)((uint8_t *)data+data->cmdsize);
    *enc=(struct encryption_info_command_64){.cmd=LC_ENCRYPTION_INFO_64,.cmdsize=sizeof *enc,.cryptoff=start,.cryptsize=amount,.cryptid=1};
    mh->sizeofcmds=text->cmdsize+data->cmdsize+sizeof *enc;
    uint32_t *code=(void *)plain, *stub=(void *)(plain+0x40);
    code[0]=0xa9417bfd; // LDP X29, X30, [SP, #16]
    code[1]=0x910083ff; // ADD SP, SP, #32
    code[2]=0x1400000e; // B __stubs
    stub[0]=0x90000030; stub[1]=0xf9400210; stub[2]=0xd61f0200;
    char path[]="/tmp/unfairplayed-tail-test.XXXXXX"; int fd=mkstemp(path); assert(fd>=0);
    save_fixture(fd,image,length); fp_slice_t slice; int count=0; char error[128];
    assert(fp_parse(path,&slice,1,&count,error,sizeof error)==0 && count==1);
    assert(tail_call_plaintext_valid(fd,&slice,plain)); assert(code_words(plain,amount)==0);
    stub[0]=0xd503201f; stub[1]=0x58000010|(((0x8000-(start+0x44))/4)<<5);
    assert(tail_call_plaintext_valid(fd,&slice,plain)); // Linker-relaxed literal stub.
    stub[1]+=1<<5; assert(!tail_call_plaintext_valid(fd,&slice,plain)); stub[1]-=1<<5;
    stub[2]=0xd61f0220; assert(!tail_call_plaintext_valid(fd,&slice,plain)); stub[2]=0xd61f0200;
    code[2]|=0x80000000; assert(!tail_call_plaintext_valid(fd,&slice,plain)); code[2]&=~0x80000000;
    code[1]=0x910043ff; assert(!tail_call_plaintext_valid(fd,&slice,plain)); code[1]=0x910083ff;
    code[0]=0xa9017bfd; assert(!tail_call_plaintext_valid(fd,&slice,plain)); code[0]=0xa9417bfd;
    pointer->flags=S_REGULAR; save_fixture(fd,image,length);
    assert(!tail_call_plaintext_valid(fd,&slice,plain)); pointer->flags=S_LAZY_SYMBOL_POINTERS;
    sections[1].offset=start-4; save_fixture(fd,image,length);
    assert(!tail_call_plaintext_valid(fd,&slice,plain)); sections[1].offset=start+0x40;
    sections[0].size=0; save_fixture(fd,image,length); assert(!tail_call_plaintext_valid(fd,&slice,plain));
    sections[0].size=12; save_fixture(fd,image,length); memset(plain,0,amount);
    assert(!tail_call_plaintext_valid(fd,&slice,plain));
    fp_attempt_t attempt={.mremap_ret=0,.pages_total=1,.pages_ok=1,.changed=true,.ent_before=7.99,.ent_after=1.96,.tail_call_layout=true};
    assert(attempt_looks_decrypted(&attempt)); attempt.tail_call_layout=false; assert(!attempt_looks_decrypted(&attempt));
    attempt.tail_call_layout=true; attempt.pages_ok=0; assert(!attempt_looks_decrypted(&attempt));
    attempt.pages_ok=1; attempt.mremap_ret=-1; assert(!attempt_looks_decrypted(&attempt));
    close(fd); unlink(path); free(image); free(plain);
}


static void test_export_removes_32bit_and_preserves_64bit(void) {
    const size_t length=0xc000, slice_size=0x1000;
    uint8_t *image=calloc(length,1); assert(image);
    struct fat_header *header=(void *)image;
    header->magic=OSSwapHostToBigInt32(FAT_MAGIC); header->nfat_arch=OSSwapHostToBigInt32(2);
    struct fat_arch *arch=(void *)(header+1);
    arch[0]=(struct fat_arch){.cputype=OSSwapHostToBigInt32(CPU_TYPE_ARM),.offset=OSSwapHostToBigInt32(0x4000),.size=OSSwapHostToBigInt32(slice_size),.align=OSSwapHostToBigInt32(14)};
    arch[1]=(struct fat_arch){.cputype=OSSwapHostToBigInt32(CPU_TYPE_ARM64),.offset=OSSwapHostToBigInt32(0x8000),.size=OSSwapHostToBigInt32(slice_size),.align=OSSwapHostToBigInt32(14)};
    struct mach_header_64 *mh=(void *)(image+0x8000);
    *mh=(struct mach_header_64){.magic=MH_MAGIC_64,.cputype=CPU_TYPE_ARM64,.filetype=MH_DYLIB,.ncmds=1,.sizeofcmds=sizeof(struct encryption_info_command_64)};
    struct encryption_info_command_64 *enc=(void *)(mh+1);
    *enc=(struct encryption_info_command_64){.cmd=LC_ENCRYPTION_INFO_64,.cmdsize=sizeof *enc,.cryptoff=0x800,.cryptsize=0x800,.cryptid=0};
    memset(image+0x4000,0x81,slice_size); // An obsolete encrypted slice must never be treated as decrypted.
    char source[]="/tmp/unfairplayed-fat-source.XXXXXX", output[]="/tmp/unfairplayed-fat-output.XXXXXX";
    int in=mkstemp(source),out=mkstemp(output);assert(in>=0 && out>=0);save_fixture(in,image,length);close(out);
    assert(fp_decrypt_file(source,output,NULL,NULL)==1);
    out=open(output,O_RDONLY);struct stat st;assert(fstat(out,&st)==0 && st.st_size==slice_size);
    uint8_t *result=malloc(slice_size);assert(result && pread_full(out,result,slice_size,0));
    assert(memcmp(result,image+0x8000,slice_size)==0);close(out);
    uint32_t magic;assert(pread_full(in,&magic,4,0) && magic==FAT_CIGAM); // Source unchanged.
    // Multiple 64-bit architectures retain their original bytes and offsets.
    header->nfat_arch=OSSwapHostToBigInt32(3);
    arch[2]=arch[1];arch[2].cpusubtype=OSSwapHostToBigInt32(CPU_SUBTYPE_ARM64E);arch[2].offset=OSSwapHostToBigInt32(0xa000);
    memcpy(image+0xa000,image+0x8000,slice_size);((struct mach_header_64 *)(image+0xa000))->cpusubtype=CPU_SUBTYPE_ARM64E;
    save_fixture(in,image,length);assert(fp_decrypt_file(source,output,NULL,NULL)==1);
    fp_slice_t slices[FP_MAX_SLICES];int count=0;char error[128];
    assert(fp_parse(output,slices,FP_MAX_SLICES,&count,error,sizeof error)==0 && count==2);
    assert(slices[0].slice_off==0x8000 && slices[1].slice_off==0xa000 && slices[1].cpusubtype==CPU_SUBTYPE_ARM64E);
    out=open(output,O_RDONLY);assert(pread_full(out,result,slice_size,0xa000) && !memcmp(result,image+0xa000,slice_size));close(out);
    // Reject an architecture entry pointing past EOF rather than reporting success.
    arch[0].offset=OSSwapHostToBigInt32(length+1);save_fixture(in,image,length);
    assert(fp_decrypt_file(source,output,NULL,NULL)==-1);
    // FAT64 architecture tables use 64-bit offsets and are normalized too.
    memset(image,0,0x1000); header=(void *)image;
    header->magic=OSSwapHostToBigInt32(FAT_MAGIC_64);header->nfat_arch=OSSwapHostToBigInt32(2);
    struct fat_arch_64 *wide=(void *)(header+1);
    wide[0]=(struct fat_arch_64){.cputype=OSSwapHostToBigInt32(CPU_TYPE_ARM),.offset=OSSwapHostToBigInt64(0x4000),.size=OSSwapHostToBigInt64(slice_size),.align=OSSwapHostToBigInt32(14)};
    wide[1]=(struct fat_arch_64){.cputype=OSSwapHostToBigInt32(CPU_TYPE_ARM64),.offset=OSSwapHostToBigInt64(0x8000),.size=OSSwapHostToBigInt64(slice_size),.align=OSSwapHostToBigInt32(14)};
    save_fixture(in,image,length);assert(fp_decrypt_file(source,output,NULL,NULL)==1);
    out=open(output,O_RDONLY);assert(pread_full(out,result,slice_size,0) && !memcmp(result,image+0x8000,slice_size));close(out);
    close(in);unlink(source);unlink(output);free(result);free(image);
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
    test_tail_call_without_ret();
    test_export_removes_32bit_and_preserves_64bit();
    puts("Data-only layout and incomplete/zero-page rejection checks passed");
    return 0;
}
