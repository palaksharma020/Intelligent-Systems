package com.secure.android.secureagent;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.os.Build;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.NumberPicker;
import java.lang.reflect.Method;
public class MainActivity extends AppCompatActivity {

    WebView webView;
    WebSettings webView_setting;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        webView = (WebView) findViewById(R.id.webView);
        webView.setWebViewClient(new WebViewClient());
        webView_setting = webView.getSettings();
        webView_setting.setJavaScriptEnabled(true);
        webView_setting.setJavaScriptCanOpenWindowsAutomatically(true);
        webView_setting.setAllowFileAccess(true);
        webView_setting.setUseWideViewPort(false);
        webView.loadUrl("file:///android_asset/UserInput.html");
    }
}
