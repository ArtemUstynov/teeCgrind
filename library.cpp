
#include <iostream>


#include <iostream>
#include <windows.h>
#include <map>
#include <sstream>
#include <string>

void MallocDebug_Done();

void MallocDebug_Init();

using namespace std;

void *(*original_malloc)(size_t);

void (*original_free)(void *);

void *(*original_calloc)(size_t, size_t);

void *(*original_realloc)(void *, size_t);

void memory_check();

//map<string, size_t> mem_track;

typedef struct MemTrack {
    void *pointer = NULL;
    size_t size = 0;
    bool free = true;
} MemTrack;
#define MAX_OPERATIONS 10000000
MemTrack mem_track[MAX_OPERATIONS];
int COUNT = 0;
int *a;
bool ORIGINAL_IAT = true;

DWORD orig_mal_page, orig_free_page, orig_cal_page, orig_rel_page = 0x02;

bool change_pointer_memory(void *pointer, size_t size) {
    for (int i = 0; i < COUNT; i++) {
        if (mem_track[i].pointer == pointer && !mem_track[i].free) {
            mem_track[i].size = size;
            return true;
        }
    }
    return false;
}

bool free_pointer(void *pointer) {
    for (int i = 0; i < COUNT; i++) {
        if (mem_track[i].pointer == pointer && !mem_track[i].free) {
            mem_track[i].size = 0;
            mem_track[i].free = true;
            return true;
        }
    }
    return false;
}

void track_new_pointer(void *pointer, size_t size) {
    if (COUNT == MAX_OPERATIONS) {
        printf("CAN'T TRACK MEMORY OPERATIONS PAST OP#: %d\n", COUNT);
        return;
    }
    mem_track[COUNT].pointer = pointer;
    mem_track[COUNT].size = size;
    mem_track[COUNT].free = false;
    COUNT++;
}

bool pointer_present(void *pointer) {

    for (int c = 0; c < COUNT; c++) {
        if (mem_track[c].pointer == pointer && !mem_track[c].free) {
            return true;
        }
    }
    return false;
}

void *MallocDebug_malloc(size_t allocated_bytes) {
    void *mem_space = original_malloc(allocated_bytes);
//    printf("malloc\n");
    if (errno != 0) {
        printf("Malloc failed on system level with error: %d \n", errno);
    } else {
        track_new_pointer(mem_space, allocated_bytes);
    }
    return mem_space;
}

void MallocDebug_free(void *pointer) {
    bool unknown_pointer = false;
    if (pointer != NULL) {
        if (!pointer_present(pointer)) {
            printf("Pointer %08x isn't tracked op# %d. Free operation might fail\n", (size_t) pointer, COUNT);
            fflush(stdout);
            unknown_pointer = true;
        }
    }
    original_free(pointer);
    if (errno != 0) {
        printf("Free failed on system level with error: %d \n", errno);
    } else {
        if (pointer == NULL) return;
        auto res = free_pointer(pointer);
        if (!res && !unknown_pointer) {
            printf("tried to free pointer that is not there %08x\n", (size_t) pointer);
        }
        if (unknown_pointer)
            printf("Free of untracked pointer success. if more pointers exist"
                   " before MallocDebug_Init or operation limit %d at capacity (%d)"
                   " undetectable memory leaks are possible\n", COUNT, COUNT == MAX_OPERATIONS);
    }

}

void *MallocDebug_calloc(size_t number, size_t size) {
    void *mem_space = original_calloc(number, size);
    if (errno != 0) {
        printf("Calloc failed on system level with error: %d \n", errno);
    } else {
        track_new_pointer(mem_space, number * size);
    }

    return mem_space;
}

void *MallocDebug_realloc(void *old_pointer, size_t size) {
    bool unknown_pointer = false;
    if (old_pointer != NULL) {
        if (!pointer_present(old_pointer)) {
            printf("Pointer %08x isn't tracked op# %d. Realloc operation might fail\n", (size_t) old_pointer, COUNT);
            fflush(stdout);
            unknown_pointer = true;
        }
    }

    void *new_pointer = original_realloc(old_pointer, size);

    if (errno != 0) {
        printf("Realloc failed on system level with error: %d \n", errno);
    } else {
        if (size != 0 || old_pointer == NULL) { //
            if (old_pointer == new_pointer && !unknown_pointer)
                change_pointer_memory(old_pointer, size);
            else {
                track_new_pointer(new_pointer, size);
            }
            if (unknown_pointer)
                printf("Pointer %08x  was defined outside of scope and is now tracked \n", (size_t) old_pointer);
        } else {
            auto res = free_pointer(old_pointer);
            if (!res && !unknown_pointer) {
                printf("tried to free pointer that is not there %08x\n", (size_t) old_pointer);
            }
            if (unknown_pointer)
                printf("Free of untracked pointer success. if more pointers exist"
                       " before MallocDebug_Init or operation limit %d at capacity (%d)"
                       " undetectable memory leaks are possible\n", COUNT, COUNT == MAX_OPERATIONS);
        }

        // if returned pointer is different from original
        // this is still needed otherwise false memory leaks can be reported
        if (old_pointer != new_pointer) {
            if (old_pointer != NULL) {
                free_pointer(old_pointer);
            }
        }

    }

    return new_pointer;
}

void MallocDebug_Init() {
    if (!ORIGINAL_IAT) return;
    HMODULE hPEFile = GetModuleHandle(NULL); // NULL means the current process
    auto pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;
    auto pNTHeaders = (PIMAGE_NT_HEADERS) (((BYTE *) pDosHeader) + pDosHeader->e_lfanew);
    auto pImageImpDescArray = (PIMAGE_IMPORT_DESCRIPTOR)
            (pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress +
             ((BYTE *) pDosHeader));
    size_t size = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size /
                  sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (size_t i = 0; i < size; i++) {
        if (pImageImpDescArray[i].Characteristics == NULL) break;
        if (strcmp("ucrtbased.dll", (char *) (pImageImpDescArray[i].Name + ((BYTE *) pDosHeader))) == 0) {
//            cout << (char *) (pImageImpDescArray[i].Name + ((BYTE *) pDosHeader)) << endl;
            auto pOriginalThunkArr = (PIMAGE_THUNK_DATA) (pImageImpDescArray[i].OriginalFirstThunk +
                                                          ((BYTE *) pDosHeader));
            /**Save original page access values loop**/
            int vp_res = 0;
            DWORD prev_vp_val = 9;
            for (int c = 0; true; c++) {
                if (pOriginalThunkArr[c].u1.AddressOfData == 0) break;
                auto funk = (PIMAGE_IMPORT_BY_NAME) (pOriginalThunkArr[c].u1.AddressOfData + ((BYTE *) pDosHeader));
//            cout << "\t" << hex << funk->Hint << " " << funk->Name << endl;
                if (strcmp("malloc", funk->Name) == 0) {
                    auto pThunkArr = (PIMAGE_THUNK_DATA) (pImageImpDescArray[i].FirstThunk + ((BYTE *) pDosHeader));
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), PAGE_READWRITE, &orig_mal_page);
                    if (vp_res == 0 && orig_mal_page != PAGE_READWRITE) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                    original_malloc = (void *(*)(size_t)) pThunkArr[c].u1.Function;
                    pThunkArr[c].u1.Function = (DWORD) MallocDebug_malloc;

                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), orig_mal_page, &prev_vp_val);
                    if (vp_res == 0 && orig_mal_page != prev_vp_val) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                } else if (strcmp("free", funk->Name) == 0) {
                    auto pThunkArr = (PIMAGE_THUNK_DATA) (pImageImpDescArray[i].FirstThunk + ((BYTE *) pDosHeader));
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), PAGE_READWRITE, &orig_free_page);
                    if (vp_res == 0 && orig_free_page != PAGE_READWRITE) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                    original_free = (void (*)(void *)) pThunkArr[c].u1.Function;
                    pThunkArr[c].u1.Function = (DWORD) MallocDebug_free;
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), orig_free_page, &prev_vp_val);
                    if (vp_res == 0 && orig_free_page != prev_vp_val) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                } else if (strcmp("calloc", funk->Name) == 0) {
                    auto pThunkArr = (PIMAGE_THUNK_DATA) (pImageImpDescArray[i].FirstThunk + ((BYTE *) pDosHeader));
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), PAGE_READWRITE, &orig_cal_page);
                    if (vp_res == 0 && orig_cal_page != PAGE_READWRITE) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                    original_calloc = (void *(*)(size_t, size_t)) pThunkArr[c].u1.Function;
                    pThunkArr[c].u1.Function = (DWORD) MallocDebug_calloc;
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), orig_cal_page, &prev_vp_val);
                    if (vp_res == 0 && orig_cal_page != prev_vp_val) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                } else if (strcmp("realloc", funk->Name) == 0) {
                    auto pThunkArr = (PIMAGE_THUNK_DATA) (pImageImpDescArray[i].FirstThunk + ((BYTE *) pDosHeader));
                    vp_res = VirtualProtect(pThunkArr + c, 1, PAGE_READWRITE, &orig_rel_page);
                    if (vp_res == 0 && orig_rel_page != PAGE_READWRITE) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                    original_realloc = (void *(*)(void *, size_t)) pThunkArr[c].u1.Function;
                    pThunkArr[c].u1.Function = (DWORD) MallocDebug_realloc;
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), orig_rel_page, &prev_vp_val);
                    if (vp_res == 0 && orig_rel_page != prev_vp_val) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                }
            }
        }
    }
    ORIGINAL_IAT = false;
}

void MallocDebug_Done() {
    if (ORIGINAL_IAT) return;
    HMODULE hPEFile = GetModuleHandle(NULL); // NULL means the current process
    auto pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;
    auto pNTHeaders = (PIMAGE_NT_HEADERS) (((BYTE *) pDosHeader) + pDosHeader->e_lfanew);
    auto pImageImpDescArray = (PIMAGE_IMPORT_DESCRIPTOR)
            (pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress +
             ((BYTE *) pDosHeader));
    size_t size = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size /
                  sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (size_t i = 0; i < size; i++) {
        if (pImageImpDescArray[i].Characteristics == NULL) break;
        if (strcmp("ucrtbased.dll", (char *) (pImageImpDescArray[i].Name + ((BYTE *) pDosHeader))) == 0) {
            auto pOriginalThunkArr = (PIMAGE_THUNK_DATA) (pImageImpDescArray[i].OriginalFirstThunk +
                                                          ((BYTE *) pDosHeader));

            int vp_res = 0;
            DWORD prev_vp_val = 9;

            for (int c = 0; true; c++) {
                if (pOriginalThunkArr[c].u1.AddressOfData == 0) break;
                auto funk = (PIMAGE_IMPORT_BY_NAME) (pOriginalThunkArr[c].u1.AddressOfData + ((BYTE *) pDosHeader));
//            cout << "\t" << hex << funk->Hint << " " << funk->Name << endl;
                if (strcmp("malloc", funk->Name) == 0) {
                    auto pThunkArr = (PIMAGE_THUNK_DATA) (pImageImpDescArray[i].FirstThunk + ((BYTE *) pDosHeader));
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), PAGE_READWRITE, &orig_mal_page);
                    if (vp_res == 0 && orig_mal_page != PAGE_READWRITE) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                    pThunkArr[c].u1.Function = (DWORD) original_malloc;
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), orig_mal_page, &prev_vp_val);
                    if (vp_res == 0 && orig_mal_page != prev_vp_val) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                } else if (strcmp("free", funk->Name) == 0) {
                    auto pThunkArr = (PIMAGE_THUNK_DATA) (pImageImpDescArray[i].FirstThunk + ((BYTE *) pDosHeader));
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), PAGE_READWRITE, &orig_free_page);
                    if (vp_res == 0 && orig_free_page != PAGE_READWRITE) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                    pThunkArr[c].u1.Function = (DWORD) original_free;
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), orig_free_page, &prev_vp_val);
                    if (vp_res == 0 && orig_free_page != prev_vp_val) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                } else if (strcmp("calloc", funk->Name) == 0) {
                    auto pThunkArr = (PIMAGE_THUNK_DATA) (pImageImpDescArray[i].FirstThunk + ((BYTE *) pDosHeader));
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), PAGE_READWRITE, &orig_cal_page);
                    if (vp_res == 0 && orig_cal_page != PAGE_READWRITE) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                    pThunkArr[c].u1.Function = (DWORD) original_calloc;
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), orig_cal_page, &prev_vp_val);
                    if (vp_res == 0 && orig_cal_page != prev_vp_val) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                } else if (strcmp("realloc", funk->Name) == 0) {
                    auto pThunkArr = (PIMAGE_THUNK_DATA) (pImageImpDescArray[i].FirstThunk + ((BYTE *) pDosHeader));
                    vp_res = VirtualProtect(pThunkArr + c, 1, PAGE_READWRITE, &orig_rel_page);
                    if (vp_res == 0 && orig_rel_page != PAGE_READWRITE) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                    pThunkArr[c].u1.Function = (DWORD) original_realloc;
                    vp_res = VirtualProtect(pThunkArr + c, sizeof(pThunkArr[c]), orig_rel_page, &prev_vp_val);
                    if (vp_res == 0 && orig_rel_page != prev_vp_val) {
                        printf("critical init error Virtual Protect fail. shutting down immediately!");
                        exit(2);
                    }
                }
            }
        }
    }
    memory_check();
    ORIGINAL_IAT = true;
}



void memory_check() {
    bool fail = false;
    FILE * fPtr;
    fPtr = fopen("errors.txt", "w");
    if(fPtr == NULL)
    {
        printf("Unable to create file.\n");
        exit(EXIT_FAILURE);
    }


    for (int c = 0; c < COUNT; c++) {
        if (!mem_track[c].free) {
            if (!fail){
                printf("FAILED TO FREE!\n" );
                fprintf(fPtr,"FAILED TO FREE!\n" );}
            printf("op # %d pointer: %08x bytes: %d \n", c, (size_t) mem_track[c].pointer, mem_track[c].size);
            fprintf(fPtr,"op # %d pointer: %08x bytes: %d \n", c, (size_t) mem_track[c].pointer, mem_track[c].size);
            fail = true;
        }
        mem_track[c].pointer = NULL;
        mem_track[c].size = 0;
        mem_track[c].free = true;
    }
    COUNT = 0;

    fflush(stdout);
    fclose(fPtr);

    if (fail){
        exit(1);
    }
    printf("MEMORY OK\n");
}


BOOL WINAPI DllMain(
        HINSTANCE hinstDLL,  // handle to DLL module
        DWORD fdwReason,     // reason for calling function
        LPVOID lpReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH:
            MallocDebug_Init();
            break;

        case DLL_THREAD_ATTACH:
            // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:

            break;

        case DLL_PROCESS_DETACH:
            MallocDebug_Done();
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
