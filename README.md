## FingerprintPlugin



#### Platforms 

- Android 



#### Installation

```
ionic cordova plugin add https://github.com/CriptoCosmo/cordova-fingerprint-plugin.git
```
```
ionic cordova plugin remove https://github.com/CriptoCosmo/cordova-fingerprint-plugin.git
```



#### Usage

```javascript
var pin = '1234'; 

cordova.plugins.FingerprintPlugin.authenticate(pin,function(){
  console.log("success");
},function(err){
    console.log(err);
})
```

