#include <elf.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>

int     find_section(const char *name, void *binary, size_t *size_section)
{
    Elf64_Ehdr  *cast_addr = binary;
    Elf64_Shdr  *tmp = binary + cast_addr->e_shoff;
    char        *name_tmp = 0;

    for (Elf64_Half i = 0; i < cast_addr->e_shnum; ++i)
    {
        name_tmp = tmp[cast_addr->e_shstrndx].sh_offset + binary + tmp[i].sh_name;
        if (!strcmp(name_tmp, name))
        {
            *size_section = tmp[i].sh_size;
            return i;
        }
    }
    return -1;
}

int     encrypt_section(void *map, size_t *size_section, size_t *offset_text)
{
    int             idx = 0;
    Elf64_Shdr      *shdr = 0;
    unsigned char   *text = 0;


    if ((idx = find_section(".text", map, size_section)) == -1)
        return -1;
    shdr = map + ((Elf64_Ehdr*)map)->e_shoff;
    text = map + shdr[idx].sh_offset;
    *offset_text = shdr[idx].sh_offset;
    for (size_t i = 0; i < *size_section; ++i)
        text[i] ^= 42;
    return 0;
}

void    *map_file(char *filename, size_t *size)
{
    int     fd = 0;
    void    *map = 0;

    if ((fd = open(filename, O_RDWR)) == -1)
        return ((void*)0);
    *size = lseek(fd, 0, SEEK_END);
    if ((map = mmap(0, *size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
        return ((void*)0);
    close(fd);
    return map;
}

int     find_section_to_infect(Elf64_Phdr *phdr, int n_phdr, size_t size_payload)
{
    Elf64_Off   start = 0, end = 0;
    int         j = 0;

    for (int i = 0; i < n_phdr; ++i)
    {
        if (phdr[i].p_filesz > 0 && phdr[i].p_filesz == phdr[i].p_memsz && (phdr[i].p_flags & PF_X))
        {
            start = phdr[i].p_offset + phdr[i].p_filesz;
            end = start + size_payload;
            for (j = 0; j < n_phdr; ++j)
            {
                if (phdr[j].p_offset >= start && phdr[j].p_offset < end && phdr[j].p_filesz > 0)
                    break;
            }
            if (j == n_phdr)
                return i;
        }
    }
    return -1;
}

Elf64_Addr	find_virtual_addr64(void *map)
{
    Elf64_Ehdr *ehdr = map;
    Elf64_Phdr *phdr = map + ehdr->e_phoff;

    for (size_t i = 0; i < ehdr->e_phnum; ++i)
    {
        if (phdr[i].p_type == PT_LOAD)
            return phdr[i].p_vaddr;
    }
    return 0;
}

int    insert_payload(void *map, int idx, char *payload, int size_payload,
                      size_t size_file, size_t size_text, size_t offset_text)
{
    Elf64_Ehdr  *ehdr = map;
    Elf64_Phdr  *phdr = ehdr->e_phoff + map;
    Elf64_Off   start = 0, offset = 0;
    Elf64_Word  virtual_addr = 0;

    if (phdr[idx].p_offset + phdr[idx].p_filesz >= size_file)
        return -1;
    start = phdr[idx].p_vaddr + phdr[idx].p_filesz;
    offset = ehdr->e_entry - (start + size_payload);
    *(Elf64_Word*)(payload + size_payload - 4) = (Elf64_Word)offset;
    ehdr->e_entry = start;
    virtual_addr = find_virtual_addr64(map) + offset_text;

    memcpy(payload + 2, &start, sizeof(Elf64_Word));
    memcpy(payload + 8, &size_text, sizeof(Elf64_Word));
    memcpy(payload + 14, &virtual_addr, sizeof(Elf64_Word));

    memcpy(map + phdr[idx].p_offset + phdr[idx].p_filesz, payload, size_payload);
    phdr[idx].p_filesz += size_payload;
    phdr[idx].p_memsz += size_payload;
    return 0;
}

int     main(int ac, char **av)
{
    if (ac < 2)
        return 1;

    char payload[] = "\x41\xbd\xff\xff\xff\xff\x41\xbc\xff\xff\xff\xff"
                     "\x41\xbb\xff\xff\xff\xff\x48\x8d\x3d\xe7\xff\xff"
                     "\xff\x49\xf7\xdd\x4c\x01\xef\x4c\x01\xdf\x49\x89"
                     "\xfa\x48\x81\xe7\x00\xf0\xff\xff\x48\xf7\xdf\x49"
                     "\x01\xfa\x48\xf7\xdf\x4d\x01\xd4\xb8\x0a\x00\x00"
                     "\x00\x4c\x89\xe6\xba\x07\x00\x00\x00\x0f\x05\x4c"
                     "\x01\xd7\x49\xf7\xda\x4d\x01\xd4\x48\xc7\xc0\xff"
                     "\xff\xff\xff\x4c\x89\xe2\x48\x89\xfe\x48\xff\xc0"
                     "\x80\x34\x06\x2a\x48\x39\xd0\x7c\xf4\xe9\xfb\xff\xff\xff";
    int size_payload = 110;

    size_t  offset_text = 0, size_section = 0, size_file = 0;
    int     idx_infect = 0;
    void    *map = 0;

    if ((map = map_file(av[1], &size_file)) == 0)
        return 1;
    if(encrypt_section(map, &size_section, &offset_text) == -1)
        return 1;
    if ((idx_infect = find_section_to_infect(((Elf64_Ehdr*)map)->e_phoff + map,
                                             ((Elf64_Ehdr*)map)->e_phnum,
                                             size_payload)) == -1)
        return 1;
    if (insert_payload(map, idx_infect, payload, size_payload, size_file,
                       size_section, offset_text) == -1)
        return 1;
    munmap(map, size_file);
}