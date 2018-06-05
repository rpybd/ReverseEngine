#include <windows.h>
#define ModRM             0x00000001              //含有  ModRM 
#define Imm8              0x00000002              //后面跟着1字节立即数 
#define Imm16             0x00000004              //后面跟着2字节立即数 
#define Imm66             0x00000008              //后面跟着立即数（Immediate），立即数长度得看是否有0x66前缀 
#define Addr67            0x00000010              //后面跟着偏移量（Displacement），偏移量长度得看是否有0x67前缀 
#define OneByte           0x00000020              //只有1个字节，这1个字节独立成一个指令 
#define Mxx               0x00100000              //mod != 11时才可解码 
#define TwoOpCode0F       0x00000040              //0x0F，2个opcode 
#define Group             0x00000200              //Group表  opcode 
#define Reserved          0x00000400              //保留 
#define PreSegment        0x00400000              //段前缀 
#define PreOperandSize66  0x00800000              //指令大小前缀0x66 
#define PreAddressSize67  0x01000000              //地址大小前缀0x67 
#define PreLockF0         0x02000000              //锁前缀0xF0 
#define PreRep            0x04000000              //重复前缀 
#define Prefix            (PreSegment+PreOperandSize66+PreAddressSize67+PreLockF0+PreRep) 
typedef struct  _INSTRUCTION 
{ 
  BYTE  RepeatPrefix;  //重复指令前缀 
  BYTE  SegmentPrefix;  //段前缀 
  BYTE  OperandPrefix;  //操作数大小前缀0x66 
  BYTE  AddressPrefix;  //地址大小前缀0x67 
  

  BYTE  Opcode1;    //opcode1 
  BYTE  Opcode2;    //opcode2 
  BYTE  Opcode3;    //opcode3 
  
  BYTE    Modrm;      //  modrm 
  
  BYTE  SIB;      //sib 
  
  union         //displacement联合体 
  { 
    BYTE  DispByte; 
    WORD  DispWord; 
    DWORD DispDword; 
  }Displacement; 
  
  union         //immediate联合体 
  { 
    BYTE  ImmByte; 
    WORD  ImmWord; 
    DWORD ImmDword; 
  }Immediate; 
  
  BYTE InstructionBuf[32]; //保存指令代码 
  DWORD dwInstructionLen; //返回指令长度 
    
}INSTRUCTION,*PINSTRUCTION; 
DWORD OneOpCodeMapTable[256] = {
  /*      0        1        2        3        4        5         6       7        8        9        A        B        C        D         E        F    */
  /*0*/ ModRM,   ModRM,   ModRM,   ModRM,   Imm8,    Imm66,   OneByte, OneByte, ModRM,   ModRM,   ModRM,   ModRM,   Imm8,    Imm66,   OneByte, TwoOpCode0F,
  /*1*/ ModRM,   ModRM,   ModRM,   ModRM,   Imm8,    Imm66,   OneByte, OneByte, ModRM,   ModRM,   ModRM,   ModRM,   Imm8,    Imm66,   OneByte, OneByte,
  /*2*/ ModRM,   ModRM,   ModRM,   ModRM,   Imm8,    Imm66,   Prefix,  OneByte, ModRM,   ModRM,   ModRM,   ModRM,   Imm8,    Imm66,   Prefix,  OneByte,
  /*3*/ ModRM,   ModRM,   ModRM,   ModRM,   Imm8,    Imm66,   Prefix,  OneByte, ModRM,   ModRM,   ModRM,   ModRM,   Imm8,    Imm66,   Prefix,  OneByte,
  /*4*/ OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte,
  /*5*/ OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte,
  /*6*/ OneByte, OneByte, ModRM,   ModRM,   Prefix,  Prefix,  Prefix,  Prefix,  Imm66,   ModRM,   Imm8,    ModRM,   OneByte, OneByte, OneByte, OneByte, 
  /*7*/ Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,
  /*8*/ Group,   Group,   Group,   Group,   ModRM,   ModRM,   ModRM,   ModRM,   ModRM,   ModRM,   ModRM,   ModRM,   ModRM,   ModRM,   ModRM,   Group,
  /*9*/ OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, Imm16,   OneByte, OneByte, OneByte, OneByte, OneByte, 
  /*A*/ Addr67,  Addr67,  Addr67,  Addr67,  OneByte, OneByte, OneByte, OneByte, Imm8,    Imm66,   OneByte, OneByte, OneByte, OneByte, OneByte, OneByte,   
  /*B*/ Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm66,   Imm66,   Imm66,   Imm66,   Imm66,   Imm66,   Imm66,   Imm66,   
  /*C*/ Group,   Group,   Imm16,   OneByte, ModRM,   ModRM,   Addr67,  Addr67,  Imm16,   OneByte, Imm16,   OneByte, OneByte, Imm8,    OneByte, OneByte,   
  /*D*/ Group,   Group,   Group,   Group,   Imm8,    Imm8,    Reserved,Addr67,  ModRM,   ModRM,   ModRM,   ModRM,   ModRM,   ModRM,   ModRM,   ModRM,   
  /*E*/ Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm8,    Imm66,   Imm66,   Imm16,   Imm8,    OneByte, OneByte, OneByte, OneByte, 
  /*F*/ Prefix,  Reserved,Prefix,  Prefix,  OneByte, OneByte, Group,   Group,   OneByte, OneByte, OneByte, OneByte, OneByte, OneByte, Group,   Group 
  
};
