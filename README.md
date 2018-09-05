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
cordova.plugins.FingerprintPlugin.authenticate(function(){
  console.log("success"),
},function(err){
    console.log(err)  
})
```

