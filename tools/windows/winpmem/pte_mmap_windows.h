#include "winpmem.h"
#include "pte_mmap.h"

#define MdlMappingNoExecute     0x40000000
#define MdlMappingNoExecute     0x40000000
#define NonPagedPoolNx			512

void pte_mmap_windows_delete(PTE_MMAP_OBJ *self);
PTE_MMAP_OBJ *pte_mmap_windows_new(void);
