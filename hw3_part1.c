#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_EXEC	2	//Executable file 
#define NOT_FOUND -2
#define BREAKPOINT_PLACEMENT (0xFFFFFFFFFFFFFF00)
#define BRK (0xCC)

int lookingForSection(char *secname ,Elf64_Shdr *secheader, char *strngtable , Elf64_Ehdr *header);
char *getsectionsymtab(FILE *file, Elf64_Shdr *sec_header , char *strngtable, Elf64_Ehdr *header);
char *getsectionstrtab(FILE *file, Elf64_Shdr *secheader, Elf64_Ehdr *header, char *strngtable);
Elf64_Sym *getSymb(char *sym_input , char *str_table ,Elf64_Shdr *sym_header, char *sym_table);
char *getdynamicsectionstrtab(FILE *file, Elf64_Shdr *secheader, Elf64_Ehdr *header, char *strngtable, int* offset_ptr);
int dynamic(Elf64_Shdr *secheader ,Elf64_Ehdr *header, int*  offset_dyn ,FILE *file);
bool look_dynTable(Elf64_Shdr *secheader ,Elf64_Ehdr *header, Elf64_Shdr**  current ,FILE *file);
bool checkingRelaEntry(Elf64_Rela **entry , Elf64_Shdr *curr ,char *symbol_name, FILE *file , Elf64_Sym *dynsymTab, Elf64_Off strTabOffset);
unsigned long look_dynSymbl(char *symbol_name, FILE *file, Elf64_Shdr *sectionHeaderTable , Elf64_Ehdr *header, Elf64_Off strTabOffset) ;

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
	FILE *file = fopen(exe_file_name, "r");
	if(!file)
	{
		*error_val = -3; // takes precedence over other cases
		return 0;
	}
	Elf64_Ehdr header;
	fread(&header, sizeof(header), 1, file);
	int is_exec = (header.e_type == ET_EXEC);
	//checking if the type is exe
	if (!is_exec)
	{
		*error_val = -3; // takes precedence over other cases
		return 0;
	}

	Elf64_Shdr section_header[header.e_shentsize * header.e_shnum]; //array of section headers
	fseek(file, header.e_shoff, SEEK_SET); // move to section header offset
	fread(section_header, header.e_shentsize, header.e_shnum, file); // read the section headers into the array


	Elf64_Shdr strtab = section_header[header.e_shstrndx];
	char *sh_string_table = (char *)malloc(strtab.sh_size);
	fseek(file, strtab.sh_offset, SEEK_SET);
	fread(sh_string_table, strtab.sh_size, 1, file);


	char *symbol_table = getsectionsymtab(file, section_header, sh_string_table, &header);
	char *string_table = getsectionstrtab(file, section_header, &header, sh_string_table);
	int offset_dyn = 0;
	char *dyn_string_table = getdynamicsectionstrtab(file, section_header, &header, sh_string_table, &offset_dyn);

	int symb_ind = lookingForSection(".symtab" , section_header, sh_string_table , &header);
	Elf64_Shdr symtab_header = section_header[symb_ind];

	Elf64_Sym *symb = getSymb(symbol_name , string_table ,&symtab_header , symbol_table );
	/*int is_dyn = 0;
	long dyn_sym_off = 0;
	if(dyn_string_table != NULL ){
		dyn_sym_off = look_dynSymbl(symbol_name , file, section_header, header.e_shnum, header.e_shentsize, &header,offset_dyn );
		is_dyn = 1;
	}*/
	int is_ddyn = dynamic(section_header , &header, &offset_dyn , file) ;
	int dyn_sym_off = look_dynSymbl(symbol_name , file, section_header, &header,offset_dyn );
	if (symb == NULL)
	{
		*error_val = -1;
	}else {
		if (ELF64_ST_BIND(symb->st_info) != 1)
		{
			*error_val = -2;
		}else{
			if( symb->st_shndx == SHN_UNDEF  && is_ddyn ){ 
				*error_val = 2 ;
				unsigned long ret_addr = dyn_sym_off;
				free(sh_string_table);
				free(symbol_table);
				free(string_table);
				free(dyn_string_table);
				fclose(file);
				return dyn_sym_off  ;
			}
			else{
				*error_val = 1;
				unsigned long ret_addr = symb->st_value;
				free(sh_string_table);
				free(symbol_table);
				free(string_table);
				free(dyn_string_table);
				fclose(file);
				return ret_addr  ;
			}
		}
	}
	free(sh_string_table);
	free(symbol_table);
	free(string_table);
	free(dyn_string_table);
	fclose(file);
	return 0 ;
}

int lookingForSection(char *secname ,Elf64_Shdr *secheader, char *strngtable , Elf64_Ehdr *header){
	for (int currSection = 0; currSection < header->e_shnum; currSection ++)
	{
		if (strcmp(strngtable + secheader[currSection].sh_name, secname))
		{
			continue ;
		}
		return currSection ;
	}
	return NOT_FOUND ;
}

char *getsectionsymtab(FILE *file, Elf64_Shdr *sec_header , char *strngtable, Elf64_Ehdr *header){
	int num = lookingForSection(".symtab" , sec_header , strngtable ,  header);
	if(num >= 0)
	{
		Elf64_Shdr temp_sec_header = sec_header[num];
		char *section = (char *)malloc(temp_sec_header.sh_size);
		fseek(file, temp_sec_header.sh_offset, SEEK_SET);
		fread(section, temp_sec_header.sh_size, 1, file);
		return section;
	}
	return NULL;
}

char *getsectionstrtab(FILE *file, Elf64_Shdr *secheader, Elf64_Ehdr *header, char *strngtable){
	int index = lookingForSection(".strtab" , secheader,strngtable,  header);
	if(index < 0)
	{
		return NULL;
	}
	Elf64_Shdr sec_header = secheader[index];
	char *section = (char *)malloc(sec_header.sh_size);
	fseek(file, sec_header.sh_offset, SEEK_SET);
	fread(section, sec_header.sh_size, 1, file);
	return section;
}

char *getdynamicsectionstrtab(FILE *file, Elf64_Shdr *secheader, Elf64_Ehdr *header, char *strngtable, int* offset_ptr){
	int index = lookingForSection(".dynstr" , secheader,strngtable,  header);
	if(index < 0)
	{
		return NULL;
	}
	Elf64_Shdr sec_header = secheader[index];
	char *section = (char *)malloc(sec_header.sh_size);
	fseek(file, sec_header.sh_offset, SEEK_SET);
	fread(section, sec_header.sh_size, 1, file);
	*offset_ptr = ((Elf64_Shdr *)section)->sh_offset;
	return section;
}

int dynamic(Elf64_Shdr *secheader ,Elf64_Ehdr *header, int*  offset_dyn ,FILE *file){
	Elf64_Shdr *current = secheader;
	int i = 0 ;
	while( i < header->e_shnum){
		if(current->sh_type == 3){
			size_t len_name = strlen(".dynstr") + 1;
    			fseek(file, secheader[header->e_shstrndx].sh_offset + current->sh_name, SEEK_SET);
    			char *name_sym = (char*)malloc(len_name);
    			fread(name_sym, len_name, 1, file);
    			if(!(0 == strncmp(".dynstr", name_sym, len_name))){
				        current = (Elf64_Shdr *) ((char *)current + header->e_shentsize);
					i++ ;
					free(name_sym);				
					continue ;
			}else{
				free(name_sym);		
				break ;
			} 
		}else{
		current = (Elf64_Shdr *) ((char *)current + header->e_shentsize);
		i++ ;
		}
	}
    if (i != header->e_shnum ) {
        *offset_dyn = current->sh_offset;
	return 1 ;
    }
	return 0 ;
}

Elf64_Sym *getSymb(char *sym_input , char *str_table ,Elf64_Shdr *sym_header, char *sym_table){
	Elf64_Sym *saved_symbl = NULL;
	for (int j = 0; j < sym_header->sh_size / sym_header->sh_entsize ; j++ )
	{
		Elf64_Sym *curr_symbl = (Elf64_Sym *)( sym_table + (j * sym_header->sh_entsize) );
		char *sym_name = str_table + curr_symbl->st_name;

		if (strcmp(sym_name, sym_input) != 0)
		{
			continue ;
		}
		if (ELF64_ST_BIND(curr_symbl->st_info) != 1)
			{
				saved_symbl = curr_symbl;
				continue ;
			}
			saved_symbl = curr_symbl;
			break ;
	}
	return saved_symbl;
}

bool look_dynTable(Elf64_Shdr *secheader ,Elf64_Ehdr *header, Elf64_Shdr**  current ,FILE *file){
	int i = 0 ;
	*current= secheader ;
	while( i < header->e_shnum){
		if((*current)->sh_type == 0xb){
			size_t len_name = strlen(".dynsym") + 1;
    			fseek(file, secheader[header->e_shstrndx].sh_offset + (*current)->sh_name, SEEK_SET);
    			char *name_sym = (char*)malloc(len_name);
    			fread(name_sym, len_name, 1, file);
    			if(!(0 == strncmp(".dynsym", name_sym, len_name))){
				        *current = (Elf64_Shdr *) ((char *)*current + header->e_shentsize);
					i++ ;
					free(name_sym);		
					continue ;
			}else{
				free(name_sym);		
				break ;
			} 
		}else{
		*current = (Elf64_Shdr *) ((char *)*current + header->e_shentsize);
		i++ ;
		}
	}
    if (i != header->e_shnum ) {
	return true;
    }
	return false ;

}

bool checkingRelaEntry(Elf64_Rela **entry , Elf64_Shdr *curr ,char *symbol_name, FILE *file , Elf64_Sym *dynsymTab, Elf64_Off strTabOffset){
        	for (int i = 0; i < curr->sh_size / curr->sh_entsize ; i++) {
			Elf64_Sym *dynSymEntryP =  (Elf64_Sym*)(((char *)dynsymTab) + (curr->sh_entsize*ELF64_R_SYM((*entry)->r_info)));   
   			size_t len_name = strlen(symbol_name) + 1;
    			fseek(file, strTabOffset + dynSymEntryP->st_name , SEEK_SET);
    			char *name_sym = (char*)malloc(len_name);
    			fread(name_sym, len_name, 1, file);
    			if(!(0 == strncmp(symbol_name, name_sym, len_name))){
            		//if (!checkDynSymName(symbol_name, file, ELF64_R_SYM((*entry)->r_info), curr->sh_offset, curr->sh_size, curr->sh_entsize, dynsymTab, strTabOffset)) {
                		*entry = (Elf64_Rela *)(((char*)*entry) + curr->sh_entsize);
			  	 free(name_sym);
				continue ;
            		}else{
				 (*entry)->r_offset;
			  	 free(name_sym);
				return true ;
			}
        	}
				return false ;
}

unsigned long look_dynSymbl(char *symbol_name, FILE *file, Elf64_Shdr *sectionHeaderTable , Elf64_Ehdr *header, Elf64_Off strTabOffset) {
    // Find dynamic symbol header table
    Elf64_Shdr *curr ;
    if (!look_dynTable(sectionHeaderTable ,header , &curr ,  file )) {
        return 0;
    }

    Elf64_Sym *dynsymTab = (Elf64_Sym *)malloc( curr->sh_size);
    fseek(file, curr->sh_offset, SEEK_SET);
    fread(dynsymTab,  curr->sh_size, 1, file);
    
    
    // Get The relocation table
    curr = sectionHeaderTable;
    for (int i = 0; i < header->e_shnum; i++) {
        if (!(curr->sh_type != 4)) {
       	        Elf64_Rela *relaTab = (Elf64_Rela *)malloc(curr->sh_size);
       		fseek(file, curr->sh_offset, SEEK_SET);
       		fread(relaTab, curr->sh_size, 1, file);
		Elf64_Rela *entry = relaTab;
		if(checkingRelaEntry(&entry , curr ,symbol_name, file , dynsymTab,  strTabOffset)){
			return entry->r_offset ; 
		}
       		
        }
        curr = (Elf64_Shdr *)((char *)curr +  header->e_shentsize);

    }
    return 0;
}
