//
//  XJRSA.m
//  XJRSA
//
//  Created by 张雪剑 on 16/1/19.
//  Copyright © 2016年 Sysw1n. All rights reserved.
//

#import "XJRSA.h"
#include "xj_rsa.h"


#define DocumentsDir [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject]
#define OpenSSLRSAKeyDir [DocumentsDir stringByAppendingPathComponent:@"openssl_rsa"]
#define OpenSSLRSAPublicKeyFile [OpenSSLRSAKeyDir stringByAppendingPathComponent:@"bb12.publicKey.pem"]
#define OpenSSLRSAPrivateKeyFile [OpenSSLRSAKeyDir stringByAppendingPathComponent:@"bb12.privateKey.pem"]

@implementation XJRSA

#pragma mark - helper
- (NSString *)publicKeyPath
{
    if (_publicKey == nil || [_publicKey isEqualToString:@""]) return nil;
    
    NSMutableArray *filenameChunks = [[_publicKey componentsSeparatedByString:@"."] mutableCopy];
    NSString *extension = filenameChunks[[filenameChunks count] - 1];
    [filenameChunks removeLastObject]; // remove the extension
    NSString *filename = [filenameChunks componentsJoinedByString:@"."]; // reconstruct the filename with no extension
    
    NSString *keyPath = [[NSBundle mainBundle] pathForResource:filename ofType:extension];
    
    return keyPath;
}

- (NSString *)privateKeyPath
{
    if (_privateKey == nil || [_privateKey isEqualToString:@""]) return nil;
    
    NSMutableArray *filenameChunks = [[_privateKey componentsSeparatedByString:@"."] mutableCopy];
    NSString *extension = filenameChunks[[filenameChunks count] - 1];
    [filenameChunks removeLastObject]; // remove the extension
    NSString *filename = [filenameChunks componentsJoinedByString:@"."]; // reconstruct the filename with no extension
    
    NSString *keyPath = [[NSBundle mainBundle] pathForResource:filename ofType:extension];
    return keyPath;
}

#pragma mark - implementation
- (NSString *)publicEncrypt:(NSString *)plainText
{
    NSString *keyPath = OpenSSLRSAPublicKeyFile;
    if (keyPath == nil) return nil;
    
    char *cipherText = xj_public_encrypt([plainText UTF8String], [keyPath UTF8String]);
    
    NSString *resultStr = [NSString stringWithFormat:@"%s",cipherText];
    NSLog(@"cipherText = %s",cipherText);
    return resultStr;
}

- (NSString *)privateDecrypt:(NSString *)cipherText
{
    NSString *keyPath = OpenSSLRSAPrivateKeyFile;
    if (keyPath == nil) return nil;
    
    char *plainText = xj_private_decrypt([cipherText UTF8String], [keyPath UTF8String]);
    if (!plainText) {
        return nil;
    }
    unsigned long len = strlen(plainText);
    char *plain = malloc(len + 1);
    memcpy(plain, plainText, len + 1);
    NSLog(@"result = %@",[NSString stringWithUTF8String:plain]);
    return [NSString stringWithUTF8String:plainText];
}

- (NSString *)privateEncrypt:(NSString *)plainText
{
    NSString *keyPath = [self privateKeyPath];
    if (keyPath == nil) return nil;
    
    char *cipherText = xj_private_encrypt([plainText UTF8String], [keyPath UTF8String]);
    
    return [NSString stringWithUTF8String:cipherText];
}

- (NSString *)publicDecrypt:(NSString *)cipherText
{
    NSString *keyPath = [self publicKeyPath];
    if (keyPath == nil) return nil;
    
    char *plainText = xj_public_decrypt([cipherText UTF8String], [keyPath UTF8String]);
    
    return [NSString stringWithUTF8String:plainText];
}

#pragma mark 生成密钥对
- (BOOL)generateRSAKeyPairWithKeySize:(int)keySize
{
    
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:OpenSSLRSAKeyDir])
    {
        [fm createDirectoryAtPath:OpenSSLRSAKeyDir withIntermediateDirectories:YES attributes:nil error:nil];
        [fm createDirectoryAtPath:OpenSSLRSAPrivateKeyFile withIntermediateDirectories:YES attributes:nil error:nil];
        [fm createDirectoryAtPath:OpenSSLRSAPublicKeyFile withIntermediateDirectories:YES attributes:nil error:nil];
    }
    
    NSString *publicKeyPath = OpenSSLRSAPublicKeyFile;
    NSLog(@"publickey = %@",publicKeyPath);
    
    NSString *privateKeyPath = OpenSSLRSAPrivateKeyFile;
    NSLog(@"privatekey = %@",privateKeyPath);
    
    if (publicKeyPath== nil || privateKeyPath == nil) {
        return NO;
    }
    int result = generate_key([publicKeyPath UTF8String], [privateKeyPath UTF8String]);
    if (result ==1) {
        return YES;
    }
    return NO;
}


#pragma mark - instance method
+ (XJRSA *)sharedInstance
{
    static XJRSA *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[[self class] alloc] init];
    });
    return sharedInstance;
}

#pragma mark 返回公钥路径
- (NSString *)returnPublicKeyPath:(NSString *)publicKey
{
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:OpenSSLRSAKeyDir])
    {
        [fm createDirectoryAtPath:OpenSSLRSAKeyDir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    //格式化公钥
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
    int count = 0;
    for (int i = 0; i < [publicKey length]; ++i) {
        
        unichar c = [publicKey characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == 64) {
            [result appendString:@"\n"];
            count = 0;
        }
    }
    [result appendString:@"\n-----END PUBLIC KEY-----"];
    [result writeToFile:OpenSSLRSAPublicKeyFile
             atomically:YES
               encoding:NSASCIIStringEncoding
                  error:NULL];
    
    const char *publicKeyFileName = [OpenSSLRSAPublicKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    NSString *Str = [NSString stringWithFormat:@"%s",publicKeyFileName];
    NSLog(@"路径 = %@",Str);
    return Str;
}

#pragma mark 返回私钥路径
- (NSString *)returnPrivateKeyPath:(NSString *)privateKey
{
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:OpenSSLRSAKeyDir])
    {
        [fm createDirectoryAtPath:OpenSSLRSAKeyDir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    //格式化公钥
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN RSA PRIVATE KEY-----\n"];
    int count = 0;
    for (int i = 0; i < [privateKey length]; ++i) {
        
        unichar c = [privateKey characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == 64) {
            [result appendString:@"\n"];
            count = 0;
        }
    }
    [result appendString:@"\n-----END RSA PRIVATE KEY-----"];
    [result writeToFile:OpenSSLRSAPrivateKeyFile
             atomically:YES
               encoding:NSASCIIStringEncoding
                  error:NULL];
    NSLog(@"result = %@",result);
    const char *publicKeyFileName = [OpenSSLRSAPrivateKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    NSString *Str = [NSString stringWithFormat:@"%s",publicKeyFileName];
    NSLog(@"路径 = %@",Str);
    return Str;
    
}

@end
