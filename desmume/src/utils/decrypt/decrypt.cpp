//taken from ndstool and modified trivially
//http://devkitpro.svn.sourceforge.net/viewvc/devkitpro/trunk/tools/nds/ndstool/source/encryption.cpp?revision=1565

/* decrypt.cpp - this file is part of DeSmuME
 *
 * Copyright (C) 2006 Rafael Vuijk
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "decrypt.h"

#include <stdlib.h>
#include <string.h>

#include "crc.h"
#include "header.h"

//encr_data
const unsigned char arm7_key[4168] =
{0,};

u32 card_hash[0x412];
int cardheader_devicetype = 0;
u32 global3_x00, global3_x04;	// RTC value
u32 global3_rand1;
u32 global3_rand3;

static u32 lookup(u32 *magic, u32 v)
{
	u32 a = (v >> 24) & 0xFF;
	u32 b = (v >> 16) & 0xFF;
	u32 c = (v >> 8) & 0xFF;
	u32 d = (v >> 0) & 0xFF;

	a = magic[a+18+0];
	b = magic[b+18+256];
	c = magic[c+18+512];
	d = magic[d+18+768];

	return d + (c ^ (b + a));
}

static void encrypt(u32 *magic, u32 *arg1, u32 *arg2)
{
	u32 a,b,c;
	a = *arg1;
	b = *arg2;
	for (int i=0; i<16; i++)
	{
		c = magic[i] ^ a;
		a = b ^ lookup(magic, c);
		b = c;
	}
	*arg2 = a ^ magic[16];
	*arg1 = b ^ magic[17];
}

static void decrypt(u32 *magic, u32 *arg1, u32 *arg2)
{
	u32 a,b,c;
	a = *arg1;
	b = *arg2;
	for (int i=17; i>1; i--)
	{
		c = magic[i] ^ a;
		a = b ^ lookup(magic, c);
		b = c;
	}
	*arg1 = b ^ magic[0];
	*arg2 = a ^ magic[1];
}

static void encrypt(u32 *magic, u64 &cmd)
{
	encrypt(magic, (u32 *)&cmd + 1, (u32 *)&cmd + 0);
}

static void decrypt(u32 *magic, u64 &cmd)
{
	decrypt(magic, (u32 *)&cmd + 1, (u32 *)&cmd + 0);
}

static void update_hashtable(u32* magic, u8 arg1[8])
{
	for (int j=0;j<18;j++)
	{
		u32 r3=0;
		for (int i=0;i<4;i++)
		{
			r3 <<= 8;
			r3 |= arg1[(j*4 + i) & 7];
		}
		magic[j] ^= r3;
	}

	u32 tmp1 = 0;
	u32 tmp2 = 0;
	for (int i=0; i<18; i+=2)
	{
		encrypt(magic,&tmp1,&tmp2);
		magic[i+0] = tmp1;
		magic[i+1] = tmp2;
	}
	for (int i=0; i<0x400; i+=2)
	{
		encrypt(magic,&tmp1,&tmp2);
		magic[i+18+0] = tmp1;
		magic[i+18+1] = tmp2;
	}
}

u32 arg2[3];

static void init2(u32 *magic, u32 a[3])
{
	encrypt(magic, a+2, a+1);
	encrypt(magic, a+1, a+0);
	update_hashtable(magic, (u8*)a);
}

static void init1(u32 cardheader_gamecode)
{
	memcpy(card_hash, &arm7_key, 4*(1024 + 18));
	arg2[0] = *(u32 *)&cardheader_gamecode;
	arg2[1] = (*(u32 *)&cardheader_gamecode) >> 1;
	arg2[2] = (*(u32 *)&cardheader_gamecode) << 1;
	init2(card_hash, arg2);
	init2(card_hash, arg2);
}

static void init0(u32 cardheader_gamecode)
{
	init1(cardheader_gamecode);
	encrypt(card_hash, (u32*)&global3_x04, (u32*)&global3_x00);
	global3_rand1 = global3_x00 ^ global3_x04;		// more RTC
	global3_rand3 = global3_x04 ^ 0x0380FEB2;
	encrypt(card_hash, (u32*)&global3_rand3, (u32*)&global3_rand1);
}

// ARM9 decryption check values
#define MAGIC30		0x72636E65
#define MAGIC34		0x6A624F79

/*
 * decrypt_arm9
 */
static bool decrypt_arm9(u32 cardheader_gamecode, unsigned char *data)
{
	u32 *p = (u32*)data;

	init1(cardheader_gamecode);
	decrypt(card_hash, p+1, p);
	arg2[1] <<= 1;
	arg2[2] >>= 1;
	init2(card_hash, arg2);
	decrypt(card_hash, p+1, p);

	if (p[0] != MAGIC30 || p[1] != MAGIC34)
	{
		fprintf(stderr, "Decryption failed!\n");
		return false;
	}

	*p++ = 0xE7FFDEFF;
	*p++ = 0xE7FFDEFF;
	u32 size = 0x800 - 8;
	while (size > 0)
	{
		decrypt(card_hash, p+1, p);
		p += 2;
		size -= 8;
	}

	return true;
}

static void encrypt_arm9(u32 cardheader_gamecode, unsigned char *data)
{
	u32 *p = (u32*)data;
	if (p[0] != 0xE7FFDEFF || p[1] != 0xE7FFDEFF)
	{
		fprintf(stderr, "Encryption failed!\n");
		return;
	}
	p += 2;

	init1(cardheader_gamecode);

	arg2[1] <<= 1;
	arg2[2] >>= 1;
	
	init2(card_hash, arg2);

	u32 size = 0x800 - 8;
	while (size > 0)
	{
		encrypt(card_hash, p+1, p);
		p += 2;
		size -= 8;
	}

	p = (u32*)data;
	p[0] = MAGIC30;
	p[1] = MAGIC34;
	encrypt(card_hash, p+1, p);
	init1(cardheader_gamecode);
	encrypt(card_hash, p+1, p);
}

//the NDS contains 
//0x0000 - 0x01FF : header
//0x0200 - 0x3FFF : typically, nothing is stored here. on retail cards, you can't read from that area anyway, but im not sure if that's done in the game card or the GC bus controller on the system
//0x4000 - 0x7FFF : secure area (details in gbatek)

bool DecryptSecureArea(u8 *romheader, u8 *secure)
{
	//this looks like it will only work on little endian hosts
	Header* header = (Header*)romheader;

	int romType = DetectRomType(*header, (char*)secure);

	if(romType == ROMTYPE_INVALID)
		return false;

	// check if ROM is already encrypted
	if (romType == ROMTYPE_NDSDUMPED)
	{
		printf("Already decrypted.\n");
	}
	else if (romType >= ROMTYPE_ENCRSECURE)		// includes ROMTYPE_MASKROM
	{
		//unsigned char data[0x4000];
		//memcpy(data,romdata+0x4000,0x4000);
		//decrypt_arm9(*(u32 *)header->gamecode, data);
		//// clear data after header
		//memset(romdata+0x200,0,(0x4000-0x200));
		//// write secure 0x800
		//memcpy(romdata+0x4000,data,0x800);

		if (!decrypt_arm9(*(u32 *)header->gamecode, secure))
			return false;

		printf("Decrypted.\n");
	}
	else
	{
		printf("File doesn't appear to have a secure area.\n");
	}

	return true;
}

bool EncryptSecureArea(u8 *romheader, u8 *secure)
{
	//this looks like it will only work on little endian hosts
	Header* header = (Header*)romheader;

	int romType = DetectRomType(*header, (char*)secure);

	if(romType == ROMTYPE_INVALID)
		return false;

	if (romType == ROMTYPE_NDSDUMPED)
	{
		//unsigned char data[0x4000];
		//memcpy(data,romdata+0x4000,0x4000);
		//encrypt_arm9(*(u32 *)header->gamecode, data);
		//// clear data after header
		//memset(romdata+0x200,0,(0x4000-0x200));
		//// write secure 0x800
		//memcpy(romdata+0x4000,data,0x800);

		encrypt_arm9(*(u32 *)header->gamecode, secure);

		printf("Encrypted.\n");
	}

	return true;
}

bool CheckValidRom(u8 *header, u8 *secure)
{
	Header* hdr = (Header*)header;

	int romType = DetectRomType(*hdr, (char*)secure);

	return (romType != ROMTYPE_INVALID);
}