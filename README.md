# SWSM4
单一窗口国密4加解密C#版 Single window, SM4 encryption and decryption C # version
## 食用  
   SM4Utils sm4 = new SM4Utils();  
   sm4.secretKey = "ZVPj5......";  
   var data = "9z1XtppWEJttZMOTqo......";  
   var res = sm4.Decrypt_ECB(Hex.ToHexString(Convert.FromBase64String(data)));  
# 关键词
loadAESDecryptStr  
MuData_KXC
