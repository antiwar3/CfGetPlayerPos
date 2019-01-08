// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "windows.h"
#include "string"
#include "stdio.h"

using namespace std;

#define  GAMEBASE			0x185C7A0  
#define  TVMP_POS_BASE		0x8B4934  //模型坐标指针
#define  ARR_OFFSET			0x6288

#pragma pack(push) 
#pragma pack(1)

typedef struct _PlayObj
{
	BYTE unknow[0x144];
	float x;
	float z;
	float y;
}PlayObj,*PPlayObj;
typedef struct _PlayerInfo
{
	DWORD ModBase;			 //模型相关的数据
	BYTE  Idx;               //自己的序号
	BYTE  EnmyFlag;          //0潜伏着 ，1保卫者
	char  Name[14];			
	_PlayObj *ObjBase;       //对象地址,[OBJBASE + 144] = 角色当前坐标
	DWORD Unknow2;
	DWORD Empty2;
	DWORD C4Flag;
	DWORD Empty3;
	DWORD Unknow3;
	INT64 QQNum;
	WORD  Hp;
	WORD  KillCount;
	DWORD EmptyArr[252];
}PLAYERINFO,*PPLAYERINFO;


typedef struct _CF_Help_Data
{

	INT64 PlayerQQNum;
	int	 RoundCount;		//回合数
	int RoleIndex;
	PLAYERINFO *pRole;		//本机玩家
	PLAYERINFO *pC4_Player; //携带C4玩家

}CF_Help_Data;


#pragma pack(pop)
CF_Help_Data g_CF;
DWORD DecodeKey1(DWORD n)
{
	DWORD nRet = 0;
	__asm
	{
		pushad
			mov eax,n
			add eax,0x5F747776 
			sub eax,0x158D4D05 
			mov edx,eax
			shr eax,0x1E
			shl edx,0x2
			or eax,edx
			mov edx,eax
			shl eax,0x1A
			shr edx,6
			or eax,edx
			xor eax,0x8B2D017D
			mov nRet,eax
			popad
	}
	return nRet;
}

DWORD DecodeKey2(DWORD n)
{
	DWORD nRet = 0;
	__asm
	{
		pushad
			mov eax,n
			add eax,0x7AD15744
			sub eax,0x2B4B52A0
			xor eax,0x29285AC3
			mov edx,eax
			shl eax,0x1D
			shr edx,0x3
			or eax,edx
			mov edx,eax
			shr eax,0x2
			shl edx,0x1E
			or eax,edx
			mov nRet,eax
			popad
	}
	return nRet;
}



DWORD GetPlayerInfoArrHead()
{
	DWORD ArrBase = *(DWORD*)GAMEBASE;
	if (ArrBase!=0)
	{
		return ArrBase + ARR_OFFSET;
	}
	return 0;
}

//内部用，获取对象
PLAYERINFO* GetPlayerObjByIndex(int idx)
{
	int head = GetPlayerInfoArrHead();
	if (head!=0)
	{
		PLAYERINFO *p =(PLAYERINFO*)(head + idx * 0x428);
		if (p->ModBase != 0)
		{
			return p;
		}
	}
	return NULL;
}

//测试 指针解密
DWORD DeCodeModPointer(DWORD n,DWORD Idx)
{
	//大部分基地址原值都为常量，因为更新方便所以搞成偏移依赖一个最小的基地址，具体来源查看文档，变量名与文档对应，请勿修改该函数内变量名
	DWORD EnCodeValue = TVMP_POS_BASE + 0x1C;
	DWORD OffsetBase = TVMP_POS_BASE;          //*
	DWORD PointerTableBase= TVMP_POS_BASE + 8; 
	DWORD XBase1 = TVMP_POS_BASE + 0x40;                   
	DWORD XBase2 = TVMP_POS_BASE + 0x18;

	//加密的指针
	DWORD EnPointer = *(DWORD*)(n + 0x182C);  //偏移
	//printf("!----[序号 %d] -> 加密指针地址:%X\r\n",Idx,EnPointer);
	//指针秘钥表
	DWORD PointerTable = *(DWORD*)(PointerTableBase + 4) ^ *(DWORD*)PointerTableBase;
	//偏移基地址
	DWORD RlOffsetBase = *(DWORD*)(OffsetBase + 4) ^ *(DWORD*)OffsetBase;
	//printf("解密函数指针表:0x%X 偏移值表:0x%X\r\n",PointerTable,RlOffsetBase);
	DWORD x = (*(DWORD*)(XBase1 + Idx * 4)) ^ *(DWORD*)XBase2;

	//计算用了那个函数指针序号,里面也是加密的
	DWORD DeCodeValue1 = *(DWORD*)EnCodeValue;
	DWORD DeCodeValue2 = *(DWORD*)(EnCodeValue+4);

	//printf("序号加密值1:%X 序号加密值2:%X\r\n",DeCodeValue1,DeCodeValue2);
	//printf("序号解密值1:%X 序号解密值2:%X\r\n",DecodeKey1(DeCodeValue1),DecodeKey2(DeCodeValue2));

	DWORD zBase =DecodeKey2(DeCodeValue2) +  DecodeKey1(DeCodeValue1) * 4;

	//printf("zBase:%X\r\n",zBase);
	DWORD zi =*(DWORD*)zBase ^ *(DWORD*)(zBase + 0x190);   //偏移查看代码
	//printf("zi:%X\r\n",zi);
	DWORD z = *(WORD*)(zi + Idx * 2); 
	//printf("z:%X\r\n",z);

	//计算结果
	DWORD Offset =RlOffsetBase + x + (z & 0xFFFF) +Idx;
	//printf("指针偏移:%X\r\n",Offset);
	DWORD K = *(DWORD*)(PointerTable + Offset * 4);
	DWORD A = *(DWORD*)(PointerTable + (K & 0xFFFF) * 4 + 0x1F40); //偏移查看代码
	DWORD B = K & 0xFFFF0000;
	DWORD DeCodeCall = A ^ B;

	//printf("秘钥值:%X 秘钥:%X 解密函数地址:0x%X\r\n",A,B,DeCodeCall);
	__asm{
		lea eax,EnPointer
		push eax
		call DeCodeCall
		add esp,4
	}

	return EnPointer;
}



bool GetPlayerPosByIndex(int id,float &x,float &y,float &z)
{
	bool bRet = false;
	BYTE EnmyFlag = g_CF.pRole->EnmyFlag;
	__try
	{
		PLAYERINFO *p = GetPlayerObjByIndex(id);
		if (p!=NULL)
		{
			if (p->EnmyFlag == EnmyFlag)
			{
				x=p->ObjBase->x;
				y=p->ObjBase->y;
				z=p->ObjBase->z;
			}
			else
			{
				DWORD ModBase = DeCodeModPointer(p->ModBase,p->Idx);
				x = *(float*)(ModBase + 0xC);
				z = *(float*)(ModBase + 0x1C);
				y = *(float*)(ModBase + 0x2C);
			}
			bRet = true;
		}
	}
	__except(1)
	{
		return bRet;
	}
	return bRet;
}



bool SetHelpData()
{
	PLAYERINFO *p;
	int head = GetPlayerInfoArrHead();
	if (head!=0)
	{
		//printf("%d\r\n",sizeof(PLAYERINFO));
		for (int i=0;i<15;i++)
		{
			p=(PLAYERINFO*)(head + i * 0x428);

			if (p)
			{
				if (p->ModBase != 0)
				{
					if (p->QQNum == g_CF.PlayerQQNum)
					{
						g_CF.pRole = (PLAYERINFO*)(head + i * 0x428);
						g_CF.RoleIndex = i;
					}
					if (p->C4Flag == 1)
					{
						g_CF.pC4_Player = (PLAYERINFO*)(head + i * 0x428);
					}

					//DWORD ModBase = DeCodeModPointer(p->ModBase,i);
					//printf("%d [%X + 0x182C] = %X ->%X\r\n",i,p->ModBase,*(DWORD*)(p->ModBase + 0x182C),ModBase);
					//printf("[%x - %d] QQ:%I64u Name:%s C4Flag:%d Dead:%d\r\n",int(p),p->Unknow1,p->QQNum,p->Name,p->C4Flag,p->Hp);
				}
			}
		}
		return true;
	}
	return false;
}


int GetPlayerIndex()
{
	if (SetHelpData())
	{
		return g_CF.RoleIndex;
	}
	return -1;
}


bool GetPlayerNameByIndex(int idx, char *Name)
{
	if (Name)
	{
		PLAYERINFO *p= GetPlayerObjByIndex(idx);
		if (p!=NULL)
		{
			strcpy(Name,p->Name);
			return true;
		}
	}
	return false;
}

bool CheckPlayerDeadByIndex(int idx)
{
	PLAYERINFO *p= GetPlayerObjByIndex(idx);
	if (p!=NULL)
	{
		return p->Hp == 0;
	}
	return true;
}


bool CF_Helper_Init()
{
	//获取下QQ号,用getcommand
	const char * Cmd = GetCommandLine();
	string temp = Cmd;
	int x = temp.find("-q");
	string qq = temp.substr(x+3,temp.length()-x-3);
	g_CF.PlayerQQNum = atoi(qq.c_str());
	//printf("QQ:%d",g_CF.PlayerQQNum);    

	return true;
}


BOOL __stdcall GetPos(int iPlayer, float &x,float &y,float &z)
{
	BOOL bRet = FALSE;

	if (GetPlayerPosByIndex(iPlayer,x,y,z))
	{
		bRet = TRUE;
		printf("%d %f %f %f\n",iPlayer,x,y,z);
	}
	x = 1;y=2;z=3;
	return bRet;
}


DWORD WINAPI test(LPVOID lp)
{
	while(1)
	{
		Sleep(1000);

		int idx = GetPlayerIndex();
		if (idx > -1)
		{
			bool IsPolic = idx > 7;
			float x,y,z = 0;
			for (int i=0;i<16;i++)
			{
				if (GetPlayerPosByIndex(i,x,y,z))
				{  
					char szname[50] = {0};
					GetPlayerNameByIndex(i,szname);
					printf("[%d] 名字:%s 位置:%.2f,%.2f,%.2f  死亡:%s\r\n",i,szname,x,y,z,CheckPlayerDeadByIndex(i)?"true":"false");
				}
			}
		}
	}
	return 1;
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			if (AllocConsole())
			{

				freopen("CONIN$", "r", stdin);
				freopen("CONOUT$", "w", stdout);
				freopen("CONOUT$", "w", stderr);
			}
 
			CF_Helper_Init();
		


			CreateThread(0,0,test,0,0,0);
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

