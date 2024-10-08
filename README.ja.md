# libsesame3bt-core
SESAME 5(PRO)/Bot2/3/4/bot/サイクルをBluetooth経由で制御するためのライブラリ

## 概要
このライブラリはBluetooth LE接続で[CANDY HOUSE](https://jp.candyhouse.co/)社製のスマートロックSESAME 5、SESAME 5 PRO、SESAME Bot 2、SESAME 3、SESAME 4、SESAME bot、SESAME サイクルを制御するためのライブラリです。本ライブラリはSESAMEのメッセージ処理部分のみが含まれています。本ライブラリは[Mbed TLS](https://github.com/Mbed-TLS/mbedtls)に依存しています。

実行する環境に合わせてフレームワークやBLEライブラリを組み合わせることが可能です。

[libsesame3bt](https://github.com/homy-newfs8/libsesame3bt) はESP32 Arduino環境で NimBLE ライブラリを結合して利用可能としたライブラリです。
他の環境で利用する場合はlibsesame3btを参考に本ライブラリを使用してください。

以下の機能を実行できます。

- SESAMEのBLE Advertisement データの解析
- SESAME状態の受信
- SESAMEの操作(施錠、開錠)

## 対応機種
以下の機種に対応しています。
- [SESAME 5](https://jp.candyhouse.co/products/sesame5)
- [SESAME 5 PRO](https://jp.candyhouse.co/products/sesame5-pro)
- [SESAME Bot 2](https://jp.candyhouse.co/products/sesamebot2)
- [SESAME bot](https://jp.candyhouse.co/products/sesame3-bot)
- [SESAME 3](https://jp.candyhouse.co/products/sesame3)
- [SESAME 4](https://jp.candyhouse.co/products/sesame4)
- [SESAME サイクル](https://jp.candyhouse.co/products/sesame3-bike)

[SESAMEサイクル2](https://jp.candyhouse.co/products/sesame-bike-2)は所有していないため対応していません。

## 開発環境
以下のデバイスで開発しました。
- [M5StickC](https://docs.m5stack.com/en/core/m5stickc)
- [Seeed Studio XIAO ESP32C3](https://wiki.seeedstudio.com/XIAO_ESP32C3_Getting_Started/)

## 使用方法
- 本ライブラリは開発環境[PlatformIO](https://platformio.org/)での利用を前提としています。本ライブラリを利用するプロジェクトのlib_depsに本リポジトリのURL等を指定して組込み可能です。
- C++17コンパイラの使用が前提となっています。PlatformIO上のESP32向け開発でC++17コンパイラを利用可能にする方法については、`platformio.ini`の`build_flags`と`build_unflags`の`-std`オプションを参照してください。

## 関連リポジトリ
- [libsesame3bt](https://github.com/homy-newfs8/libsesame3bt)
ESP32 Arduino + NimBLE と結合したライブラリ
- [ESP32Sesame3App](https://github.com/homy-newfs8/ESP32Sesame3App)
libsesame3btを使ったアプリケーションサンプル
- [esphome-sesame](https://github.com/homy-newfs8/esphome-sesame3)
[ESPHome](https://esphome.io/)でSESAMEを使うための外部コンポーネント

## 制限事項
- 本ライブラリはSESAMEデバイスの初期設定を行うことができません。公式アプリで初期設定済みのSESAMEのみ制御可能です。
- ライブラリのドキュメントはありません。利用方法の概要は英語版READMEのUsageセクションに書いてあります。また[libsesame3bt](https://github.com/homy-newfs8/libsesame3bt)のソース、サンプルアプリである[ESP32Sesame3App](https://github.com/homy-newfs8/ESP32Sesame3App)、本ライブラリ自体のソースコードを参照願います。

## 謝辞

本ライブラリの開発には[pysesameos2](https://github.com/mochipon/pysesameos2)の成果を大いに参考にさせていただきました。感謝します。

困難な状況の中で開発を続けている[PlatformIO](https://platformio.org/)プロジェクトのメンバーに感謝します。

オープンソースでSDK[SesameSDK3.0 for Android](https://github.com/CANDY-HOUSE/SesameSDK_Android_with_DemoApp)を公開してくれた[CANDY HOUSE](https://jp.candyhouse.co/)様、ありがとうございます。
