//
//  ViewController.m
//  XJRSA
//
//  Created by 张雪剑 on 16/1/13.
//  Copyright © 2016年 Sysw1n. All rights reserved.
//

#import "ViewController.h"
#import "XJRSA.h"

@interface ViewController ()

@property (nonatomic, copy) NSString *cipher;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

// 生成密钥对
- (IBAction)generateAction:(id)sender{
    // 生成1024位的密钥对,可以更改其他位数
    BOOL creatRSA = [[XJRSA sharedInstance] generateRSAKeyPairWithKeySize:1024];
    NSLog(@"创建密钥对%@",creatRSA?@"成功":@"失败");
}

// 导入公钥
- (IBAction)importKey:(id)sender {
    NSString *keyPath = [[XJRSA sharedInstance] returnPublicKeyPath:@"MIGJAoGBANUMxYaJwhIJy8CM5wONx12F9PiO/7kwq2vqyjxmlDfkqX9pc3tVkZPZ2Br5z032QdrBVF3rEsQ7BNUJByOxlMQZz9rfyhBH136klJV6iCIJgOw53b0OZ0Xklbdn9Uvt2o6YUDAdm19XoZXY19ZZK0x9WDF+hMDme6SyqbXJVKNfAgMBAAE="];
    NSLog(@"keyPath = %@",keyPath);
}

// 公钥加密
- (IBAction)encryptAction:(id)sender {
    self.cipher = [[XJRSA sharedInstance] publicEncrypt:@"当下网络安全问题日益严峻,越来越多的开发者或公司开始选用安全性比较强的rsa加解密方式,本demo是集生成rsa密钥对,导入字符串公钥/密钥,公钥加密,私钥解密等多种rsa使用方法,帮助大家在iOS开发中更好更方便的为自己的数据加密!~ 后续将持续更新,增加更多功能,优化代码的可用性!"];
}

// 私钥解密
- (IBAction)decipherAction:(id)sender {
    NSString *result = [[XJRSA sharedInstance] privateDecrypt:self.cipher];
    NSLog(@"解密结果 = %@",result);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
