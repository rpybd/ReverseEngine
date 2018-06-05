// TranverseASM.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "ReverseASM.h"

#define MAX 3200

//store ins
char strSeq[MAX] = { 0 };
unsigned int hexSeq[MAX] = { 0 };
//total len of ins
int totalLenofIns;

//well formated ins
INSTRUCTION target[400];

int ModRMTbl(int mod, int reg, int r_m, int regSize, int r_mSize, char* firOpr_m, char* secOpr_m);
int SIBTbl(int ss, int index, int base, char* SIB_index, char* SIB_base);

int main(int argc, char const *argv[])
{

	//fopen
	FILE* fd = fopen("C:\\Users\\Oz\\Desktop\\2017下\\逆向\\crackmeBin.txt", "r");
	//read string
	fscanf(fd, "%s", strSeq);
	hexSeq[MAX];
	//tranverse string to int by byte
	int str2intCount = strlen(strSeq);
	totalLenofIns = str2intCount;
	while (str2intCount) {
		int i = totalLenofIns - str2intCount;
		if ((strSeq[i] >= '0') && (strSeq[i] <= '9'))
			if (i % 2)
				hexSeq[i / 2] += strSeq[i] - 48;
			else
				hexSeq[i / 2] = 16 * (strSeq[i] - 48);
		else if ((strSeq[i] >= 'a') && (strSeq[i] <= 'f'))
			if (i % 2)
				hexSeq[i / 2] += strSeq[i] - 'a' + 10;
			else
				hexSeq[i / 2] = 16 * (strSeq[i] - 'a' + 10);
		else if ((strSeq[i] >= 'A') && (strSeq[i] <= 'F'))
			if (i % 2)
				hexSeq[i / 2] += strSeq[i] - 'A' + 10;
			else
				hexSeq[i / 2] = 16 * (strSeq[i] - 'A' + 10);

		str2intCount--;
	}
	//go to the beginning of instru
	char* firOpr_m = (char*)malloc(sizeof(char*)); //first op r/m
	char* secOpr_m = (char*)malloc(sizeof(char*)); //second op r/m
	char* SIB_index = (char*)malloc(sizeof(char*)); //SIB_index
	char* SIB_base = (char*)malloc(sizeof(char*)); //SIB_base
	unsigned int* rdPtrBack = hexSeq;                    //ptr head for translate 
	unsigned int* rdPtrFront = hexSeq;                  //ptr head for hex report

														//get M/R info
	int mod = *(rdPtrBack + 1) >> 6;
	int reg = (*(rdPtrBack + 1) << 26) >> 29;
	int r_m = (*(rdPtrBack + 1) << 29) >> 29;

	//resolve opcode to demain
	int opType = OneOpCodeMapTable[(*rdPtrBack >> 4) * 16 + (*rdPtrBack & 0x0000000F)];

	//core code part
	while (*rdPtrFront != '\0') {
		switch (opType) {//remain to be filled    

			case ModRM: {									//complex ModRM
				switch (*rdPtrBack) {
					case 0x8B: {  									//mov 8b part
																	//mov ecx, [esp+10h+argv] 8B 4C 24 18
																	//mov edx, [ecx+4]		  8B 51 04
																	//mov esi, [ecx+4]		  8B 71 04
						printf("MOV");
						rdPtrBack += 2;						//now ptr SIB

															//SIB mod
						if (r_m == 0x8 && mod != 3) {
							ModRMTbl(mod, reg, r_m, 32, 0, firOpr_m, secOpr_m);
							printf("%s, ", firOpr_m);

							//SIB procedure
							int ss = *rdPtrBack >> 6;
							int index = (*rdPtrBack << 26) >> 29;
							int base = (*rdPtrBack << 29) >> 29;

							SIBTbl(ss, index, base, SIB_index, SIB_base);
							printf("[");
							printf("%s+", SIB_base);

							//index's existense relies on table
							if (index != 8) {
								if (!ss)
									printf("%s+", SIB_index);
								else
									printf("%s*%d+", SIB_index, 2 ^ ss);
							}
						}

						//not SIB, normal partern
						else {
							ModRMTbl(mod, reg, r_m, 32, 32, firOpr_m, secOpr_m);
							printf("%s, ", firOpr_m);
							printf("[");
							printf("%s+", secOpr_m);
						}

						//displacement, relies on mod
						if (mod == 1) {
							rdPtrBack++;
							printf("%Xh", *rdPtrBack);
						}
						else if (mod == 2) {
							printf("%X%X%X%Xh", *(rdPtrBack + 4), *(rdPtrBack + 3), *(rdPtrBack + 2), *(rdPtrBack + 1));
							rdPtrBack += 4;
						}

						printf("]\n");
					} break;										//mov 8b break

					case 0x88: {									//mov 88 part
																	//mov [esp+10h+var_A], al	88 44 24 06
																	//mov [esp+10h+var_9], al	88 44 24 07
																	//mov [esp+10h+var_6], al	88 44 24 0a
																	//mov [esi+2], al			88 46 02
																	//mov [eax+5], dl 			88 50 05
																	//mov [esi+6], dl 			88 56 06
						printf("MOV");
						rdPtrBack += 2;

						//SIB mod
						if (r_m == 0x8 && mod != 3) {
							if (mod == 1)
								ModRMTbl(mod, reg, r_m, 8, 32, firOpr_m, secOpr_m);

							//SIB procedure
							int ss = *rdPtrBack >> 6;
							int index = (*rdPtrBack << 26) >> 29;
							int base = (*rdPtrBack << 29) >> 29;

							SIBTbl(ss, index, base, SIB_index, SIB_base);
							printf("[");
							printf("%s+", SIB_base);

							//index's existense relies on table
							if (index != 8) {
								if (!ss)
									printf("%s+", SIB_index);
								else
									printf("%s*%d+", SIB_index, 2 ^ ss);
							}

							//displacement, relies on mod
							if (mod == 1) {
								rdPtrBack++;
								printf("%Xh", *rdPtrBack);
							}
							else if (mod == 2) {
								printf("%X%X%X%Xh", *(rdPtrBack + 4), *(rdPtrBack + 3), *(rdPtrBack + 2), *(rdPtrBack + 1));
								rdPtrBack += 4;
							}
						}

						//not SIB, normal partern
						else {
							if (mod == 1) {
								ModRMTbl(mod, reg, r_m, 8, 32, firOpr_m, secOpr_m);
								printf("[");
								printf("%s+", secOpr_m);
								rdPtrBack++;
								printf("%Xh", *rdPtrBack);
							}

						}
						printf("], ");
						printf("%s\n", firOpr_m);
					} break;										//mov 88 break

					case 0x8A: {									//mov 8a part
																	//mov al, byte ptr [esp+10h+argc]	8A 44 24 14
																	//mov bl, al						8A D8
																	//mov al, bl						8A C3
																	//mov dl, [esi+6]					8A 56 06
						printf("MOV");
						rdPtrBack += 2;						//now ptr SIB

															//SIB mod
						if (r_m == 0x8 && mod != 3) {
							ModRMTbl(mod, reg, r_m, 8, 0, firOpr_m, secOpr_m);
							printf("%s, ", firOpr_m);

							//ptr's decided
							if (mod == 1)
								printf("byte ptr ");

							//SIB procedure
							int ss = *rdPtrBack >> 6;
							int index = (*rdPtrBack << 26) >> 29;
							int base = (*rdPtrBack << 29) >> 29;

							SIBTbl(ss, index, base, SIB_index, SIB_base);
							printf("[");
							printf("%s+", SIB_base);

							//index's existense relies on table
							if (index != 8) {
								if (!ss)
									printf("%s+", SIB_index);
								else
									printf("%s*%d+", SIB_index, 2 ^ ss);
							}

							//displacement, relies on mod
							if (mod == 1) {
								rdPtrBack++;
								printf("%Xh", *rdPtrBack);
							}
							else if (mod == 2) {
								printf("%X%X%X%Xh", *(rdPtrBack + 4), *(rdPtrBack + 3), *(rdPtrBack + 2), *(rdPtrBack + 1));
								rdPtrBack += 4;
							}

							printf("]\n");
						}

						//not SIB, normal partern
						else {
							if (mod == 1) {
								ModRMTbl(mod, reg, r_m, 8, 32, firOpr_m, secOpr_m);
								printf("%s, ", firOpr_m);
								printf("[");
								printf("%s+", secOpr_m);
								rdPtrBack++;
								printf("%Xh", *rdPtrBack);
								printf("]");
							}
							else if (mod == 3) {
								ModRMTbl(mod, reg, r_m, 8, 8, firOpr_m, secOpr_m);
								printf("%s, ", firOpr_m);
								printf("%s\n", secOpr_m);
							}
						}
					} break;										//mov 8a break

					case 0x08: {									//mov 08 part
																	//or [edx], bl	08 1A
						printf("OR ");
						ModRMTbl(mod, reg, r_m, 32, 8, firOpr_m, secOpr_m);
						printf("[");
						printf("%s, ", secOpr_m);
						printf("%s\n", firOpr_m);
					} break;										//mov 08 break

					case 0x30: {									//30 xor part
																	//xor[edx+1], bl	30 5A 01
						printf("XOR ");
						rdPtrBack += 2;

						//SIB
						if (r_m == 8 && mod != 3) {
							//
						}
						else {
							ModRMTbl(mod, reg, r_m, 8, 32, firOpr_m, secOpr_m);
							printf("[");
							printf("%s+", secOpr_m);

							//displacement, relies on mod
							if (mod == 1) {
								rdPtrBack++;
								printf("%Xh", *rdPtrBack);
							}
							else if (mod == 2) {
								printf("%X%X%X%Xh", *(rdPtrBack + 4), *(rdPtrBack + 3), *(rdPtrBack + 2), *(rdPtrBack + 1));
								rdPtrBack += 4;
							}

							printf("], ");

							printf("%s\n", firOpr_m);
						}
					} break;										//30 xor break

					case 0x2A: {									//2A sub part
																	//sub al, dl 	2A C2
						printf("SUB ");
						ModRMTbl(mod, reg, r_m, 8, 8, firOpr_m, secOpr_m);
						printf("%s, ", firOpr_m);
						printf("%s\n", secOpr_m);
					} break;										//2A sub break

					case 0x03: {									//03 add part
																	//add eax, edx 	03 C2     
						printf("ADD ");
						rdPtrBack += 2;

						//SIB
						if (r_m == 8 && mod != 3) {
							//
						}

						//not SIB, normal partern
						else {
							ModRMTbl(mod, reg, r_m, 32, 32, firOpr_m, secOpr_m);
							printf("%s, ", firOpr_m);
							printf("%s\n", secOpr_m);
						}
					} break;										//03 add break
					}
			} break;										//ModRM break
			//--------ModRM end------------//
			case Imm8: {
				//mov al, 1h			B0 01	
				//and al, 7 			24 07	
				//and dl, al			22 D0 
				//jns short loc_4010BF 	79 05
				if (*rdPtrBack == 24) {						 						//24 and imm8 to al
					printf("AND ");
					printf("al, ");
					rdPtrBack++;
					printf("%Xh\n", *rdPtrBack);
				}
				else if (*rdPtrBack == 22) {										//22 and r to r				
					printf("AND ");
					ModRMTbl(mod, reg, r_m, 8, 8, firOpr_m, secOpr_m);
					printf("%s, ", firOpr_m);
					printf("%s\n", secOpr_m);
				}
				else if (*rdPtrBack == 79) {										//79 jns to rel8
																					//unfinished
				}
				else if (*rdPtrBack - 0xB0 >= 0 && *rdPtrBack - 0xB0 < 0x08) {		//B* mov imm8 to r
					printf("MOV ");

					switch ((*rdPtrBack << 26) >> 26) {

					case 0: printf("al, "); break;
					case 2: printf("dl, "); break;
					}

					rdPtrBack++;
					printf("%X\n", *rdPtrBack);
				}
				//
				else if (*rdPtrBack - 0xB0 >= 0x09 && *rdPtrBack - 0xB0 < 0x10) {
					printf("MOV ");													//B* mov r to r

					switch ((*rdPtrBack << 26) >> 26) {

					case 2: printf("dl, "); break;
					}

					rdPtrBack++;
					printf("%X\n", *rdPtrBack);
				}
			} break;										//Imm8 break
			//--------Imm8 end------------//
			case Imm16:
			case OneByte: {									//OneByte ins

				switch (*rdPtrBack) {
					case 0x53: {									//53 push part
																	//push ebx 53
																	//push esi 56
						printf("PUSH ");
						switch (*rdPtrBack & 0x0000000F) {
						case 0: printf("EAX\n"); break;
						case 1: printf("ECX\n"); break;
						case 2: printf("EDX\n"); break;
						case 3: printf("EBX\n"); break;
						case 4: printf("ESP\n"); break;
						case 5: printf("EBP\n"); break;
						case 6: printf("ESI\n"); break;
						case 7: printf("EDI\n"); break;
						}
					} break;										//53 push break

					case 0x99: {													//99 cdq part
																	//cdq 	99
						printf("cdq\n");
					} break;										//99 cdq break
					}
			} break;										//OneByte break
			//--------OneByte end------------//
			case Group: {									//imm group
				switch (*rdPtrBack) {
					case 0x83: {                                	//83 group part
																	//sub esp 10h	83 EC 10    
																	//and edx, 3	83 E2 03  
						switch (reg) {
						case 5: printf("SUB "); break;      	//sub part
						case 4: printf("AND "); break;			//and part
						}

						//leave reg empty, depend on r_m
						ModRMTbl(mod, reg, r_m, 0, 32, firOpr_m, secOpr_m);
						printf("%s, ", secOpr_m);

						//only imm8
						rdPtrBack++;
						printf("%Xh", *rdPtrBack);
					} break;										//83 group break

					case 0xFE: {									//FE group part
																	//dec bl	FE CB
						switch (reg) {

						case 1: {						//dec part
							printf("DEC ");
							ModRMTbl(mod, reg, r_m, 0, 8, firOpr_m, secOpr_m);
							printf("%s\n", secOpr_m);
						} break;
						}
					} break;										//FE group break

					case 0xC6: {									//FE group part
																	//mov [esp+1Ch+var_10], 77h		C6 44 24 0C 77
																	//mov [esp+1Ch+var_F], 76h		C6 44 24 0D 76
																	//mov [esp+1Ch+var_E], 0CAh		C6 44 24 0E CA
																	//mov [esp+1Ch+var_D], 0F3h 	C6 44 24 0F F3
																	//mov [esp+1Ch+var_C], 0A8h 	C6 44 24 10 A8
																	//mov [esp+1Ch+var_B], 0Ch 		C6 44 24 11 0C
																	//mov [esp+1Ch+var_8], 0FEh		C6 44 24 14 FE
																	//mov [esp+1Ch+var_7], 0DBh		C6 44 24 15 DB
						printf("MOV ");
						rdPtrBack += 2;						//now ptr SIB

															//SIB mod
						if (r_m == 0x8 && mod != 3) {

							//SIB procedure
							int ss = *rdPtrBack >> 6;
							int index = (*rdPtrBack << 26) >> 29;
							int base = (*rdPtrBack << 29) >> 29;

							SIBTbl(ss, index, base, SIB_index, SIB_base);
							printf("[");
							printf("%s", SIB_base);

							//index's existense relies on table
							if (index != 4) {
								if (!ss)
									printf("%s+", SIB_index);
								else
									printf("%s*%d+", SIB_index, 2 ^ ss);
							}
							else {
								printf("+");
							}
						}

						//not SIB, normal partern
						else {
							ModRMTbl(mod, reg, r_m, 32, 32, firOpr_m, secOpr_m);
							printf("%s, ", firOpr_m);
							printf("[");
							printf("%s+", secOpr_m);
						}

						//displacement, relies on mod
						if (mod == 1) {
							rdPtrBack++;
							printf("%Xh", *rdPtrBack);
						}
						else if (mod == 2) {
							printf("%X%X%X%Xh", *(rdPtrBack + 4), *(rdPtrBack + 3), *(rdPtrBack + 2), *(rdPtrBack + 1));
							rdPtrBack += 4;
						}

						printf("], ");
						rdPtrBack++;
						printf("%Xh\n", *rdPtrBack);
					} break;										//FE group break

					case 0xF6: {									//F6 group part
																	//imul dl    				F6 EA
																	//imul byte ptr [esi+2]		F6 6E 02
						switch (reg) {
						case 5: {						//imul part
							printf("IMUL ");
							if (mod == 1) {
								ModRMTbl(mod, reg, r_m, 0, 32, firOpr_m, secOpr_m);
								printf("byte ptr ");
								printf("[");
								printf("%s+", secOpr_m);

								//displacement, relies on mod
								rdPtrBack++;
								printf("%Xh", *rdPtrBack);

								printf("]\n");
							}
							else if (mod == 3) {
								ModRMTbl(mod, reg, r_m, 0, 8, firOpr_m, secOpr_m);
								printf("%s\n", secOpr_m);
							}
						} break;						//imul break
						}
					} break;										//F6 break break

					case 0xC1: {									//C1 group part
																	//sar dl, 2  	C0 FA 02
						switch (reg) {

						case 7: printf("SAR "); break;
						}

						ModRMTbl(mod, reg, r_m, 0, 8, firOpr_m, secOpr_m);
						printf("%s, ", secOpr_m);

						rdPtrBack++;
						printf("%X\n", *rdPtrBack);
					} break;										//C1 group break

					case 0x81: {									//81 group part
																	//and edx, 80000001h	81 E2 01 00 00 80
						switch (reg) {

						case 4: printf("AND "); break;
						}

						ModRMTbl(mod, reg, r_m, 0, 32, firOpr_m, secOpr_m);
						printf("%s, ", secOpr_m);
						printf("%X%X%X%Xh", *(rdPtrBack + 4), *(rdPtrBack + 3), *(rdPtrBack + 2), *(rdPtrBack + 1));
						rdPtrBack += 4;
					} break;										//81 group break
					}
			} break;										//Group break
			//--------Group end------------//
			case 0x0F: {									//0F ins
															//movsx   eax, byte ptr [esi+2] 	0F BE 46 02
															//movsx   edx, byte ptr [esi+7] 	0F BE 56 07
				rdPtrBack++;
				mod = *(rdPtrBack + 1) >> 6;
				reg = (*(rdPtrBack + 1) << 26) >> 29;
				r_m = (*(rdPtrBack + 1) << 29) >> 29;

				switch (*rdPtrBack) {
					case 0xBE: {									//0F BE movsx part
						printf("MOVSX ");

						if (mod == 1) {
							ModRMTbl(mod, reg, r_m, 32, 32, firOpr_m, secOpr_m);
							printf("%s, ", firOpr_m);
							printf("byte ptr ");
							printf("[");
							printf("%s+", secOpr_m);
							rdPtrBack++;
							printf("%Xh\n", *rdPtrBack);
						}
					} break;										//0F BE movsx break
					}
			} break;										//0F break
		}

		//ptr next ins
		rdPtrBack++;
		while (rdPtrFront != rdPtrBack) {
			printf("%X ", *rdPtrFront);
			rdPtrFront++;
		}
	}

	system("pause");
	return 0;
}
int ModRMTbl(int mod, int reg, int r_m, int regSize, int r_mSize, char* firOpr_m, char* secOpr_m) {
	if (regSize) {
		if (regSize == 32) {
			//32 bit reg
			switch (reg) {
			case 0: strcpy(firOpr_m, "eax"); break;
			case 1: strcpy(firOpr_m, "ecx"); break;
			case 2: strcpy(firOpr_m, "edx"); break;
			case 3: strcpy(firOpr_m, "ebx"); break;
			case 4: strcpy(firOpr_m, "esp"); break;
			case 5: strcpy(firOpr_m, "ebp"); break;
			case 6: strcpy(firOpr_m, "esi"); break;
			case 7: strcpy(firOpr_m, "edi"); break;
			}
		}
		else {
			//8, 16 bit reg
			switch (reg) {
			case 0: strcpy(firOpr_m, (regSize == 8) ? "al" : "ax"); break;
			case 1: strcpy(firOpr_m, (regSize == 8) ? "cl" : "cx"); break;
			case 2: strcpy(firOpr_m, (regSize == 8) ? "dl" : "dx"); break;
			case 3: strcpy(firOpr_m, (regSize == 8) ? "bl" : "bx"); break;
			case 4: strcpy(firOpr_m, (regSize == 8) ? "ah" : "sp"); break;
			case 5: strcpy(firOpr_m, (regSize == 8) ? "ch" : "bp"); break;
			case 6: strcpy(firOpr_m, (regSize == 8) ? "dh" : "si"); break;
			case 7: strcpy(firOpr_m, (regSize == 8) ? "bh" : "di"); break;
			}
		}
	}

	//r_m
	if (r_mSize) {
		if (r_mSize == 32) {
			//32 bit reg
			switch (r_m) {
			case 0: strcpy(secOpr_m, "eax"); break;
			case 1: strcpy(secOpr_m, "ecx"); break;
			case 2: strcpy(secOpr_m, "edx"); break;
			case 3: strcpy(secOpr_m, "ebx"); break;
			case 4: {
				if (mod == 3)
					strcpy(secOpr_m, "esp");
			}  break;
			case 5: {
				if (mod != 0)
					strcpy(secOpr_m, "esp");
			}  break;
			case 6: strcpy(secOpr_m, "esi"); break;
			case 7: strcpy(secOpr_m, "edi"); break;
			}
		}
		else if (mod == 3) {
			//8, 16 bit reg
			switch (r_m) {
			case 0: strcpy(secOpr_m, (regSize == 8) ? "al" : "ax"); break;
			case 1: strcpy(secOpr_m, (regSize == 8) ? "cl" : "cx"); break;
			case 2: strcpy(secOpr_m, (regSize == 8) ? "dl" : "dx"); break;
			case 3: strcpy(secOpr_m, (regSize == 8) ? "bl" : "bx"); break;
			case 4: strcpy(secOpr_m, (regSize == 8) ? "ah" : "sp"); break;
			case 5: strcpy(secOpr_m, (regSize == 8) ? "ch" : "bp"); break;
			case 6: strcpy(secOpr_m, (regSize == 8) ? "dh" : "si"); break;
			case 7: strcpy(secOpr_m, (regSize == 8) ? "bh" : "di"); break;
			}
		}
	}

	return 0;
}
int SIBTbl(int ss, int index, int base, char* SIB_index, char* SIB_base) {
	if (index != 4) {
		switch (index) {
		case 0: strcpy(SIB_index, "eax"); break;
		case 1: strcpy(SIB_index, "ecx"); break;
		case 2: strcpy(SIB_index, "edx"); break;
		case 3: strcpy(SIB_index, "ebx"); break;
		case 5: strcpy(SIB_index, "esp"); break;
		case 6: strcpy(SIB_index, "esi"); break;
		case 7: strcpy(SIB_index, "edi"); break;
		}
	}
	else
		return 1;

	//base part
	if (base != 4) {
		switch (index) {
		case 0: strcpy(SIB_base, "eax"); break;
		case 1: strcpy(SIB_base, "ecx"); break;
		case 2: strcpy(SIB_base, "edx"); break;
		case 3: strcpy(SIB_base, "ebx"); break;
		case 5: strcpy(SIB_base, "esp"); break;
		case 6: strcpy(SIB_base, "esi"); break;
		case 7: strcpy(SIB_base, "edi"); break;
		}
	}
	else
		return 1;

	return 0;
}



