//
//  xj_base_64.h
//  XJRSA
//
//  Created by 张雪剑 on 16/1/19.
//  Copyright © 2016年 Sysw1n. All rights reserved.
//

#include <stdio.h>
#ifndef xj_base_64_h
#define xj_base_64_h

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);


#endif /* xj_base_64_h */
