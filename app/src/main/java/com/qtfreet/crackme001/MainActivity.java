package com.qtfreet.crackme001;

import android.os.Build;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {
    static {
//        Log.e("qtfreet",);
        if (Build.VERSION.SDK_INT < 20) {
            System.loadLibrary("qtfreet");
        } else {

        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
    }

    private EditText ed = null;
    private Button tv = null;


    private void initView() {
        tv = (Button) findViewById(R.id.reg);
        ed = (EditText) findViewById(R.id.scode);
        tv.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                checkCode();
            }
        });

    }

    public void checkCode() {
        String s = ed.getText().toString().trim();
        StringBuilder sb = new StringBuilder();
        sb.append(s);
        String result = sb.toString().toLowerCase().trim();
        if (check(result)) {
            Toast.makeText(MainActivity.this, "Congratulations", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(MainActivity.this, "U are wrong~", Toast.LENGTH_SHORT).show();
        }
    }


    public native boolean check(String scode);
}
