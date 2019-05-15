package com.dodola.traphooks

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        findViewById<Button>(R.id.button).setOnClickListener {
            findViewById<TextView>(R.id.sample_text).setText("1+2=" + intFromJNI())
        }
    }

    external fun intFromJNI(): Int

    companion object {
        init {
            System.loadLibrary("native-lib")
        }
    }
}
