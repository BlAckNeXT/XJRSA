//
//  xj_rsa.h
//  XJRSA
//
//  Created by 张雪剑 on 16/1/19.
//  Copyright © 2016年 Sysw1n. All rights reserved.
//

#ifndef xj_rsa_h
#define xj_rsa_h

#include <stdio.h>

char *xj_private_decrypt(const char *cipher_text, const char *private_key_path);
char *xj_public_encrypt(const char *plain_text, const char *public_key_path);
char *xj_private_encrypt(const char *plain_text, const char *private_key_path);
char *xj_public_decrypt(const char *cipher_text, const char *public_key_path);
int xj_generate_KeyPair(int keySize, const char *public_key_path, const char *private_key_path);
int generate_key(const char *public_key_path, const char *private_key_path);

#endif /* xj_rsa_h */
