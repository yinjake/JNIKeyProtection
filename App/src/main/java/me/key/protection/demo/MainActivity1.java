package me.key.protection.demo;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import me.key.protection.JNIKey;
import me.key.protection.JNISignature;

/**
 * 使用 so 文件存储私密数据，并增加签名防盗机制
 * <p>
 * https://rockycoder.cn/android%20ndk/2018/11/18/Android-NDK-DecryptKey.html
 */
public class MainActivity1 extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main2);

        TextView value = findViewById(R.id.value);
        Log.e("MainActivity", "  ---  "+"onCreate");
        try {
            Context context = this.createPackageContext("me.key.protection.demo", CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY);
            Log.e("MainActivity 0 ", "  ---  "+context);
            Log.e("MainActivity1", "  ---  "+JNISignature.getSignature(getApplicationContext()));
            boolean flag = JNIKey.init();
            Log.e("MainActivity2", "  ---  "+String.valueOf(flag));
            String key = JNIKey.getKey();
            Log.e("MainActivity3", "  ---  "+key);

            value.setText(String.format("%s%s", flag, key));
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }
}
