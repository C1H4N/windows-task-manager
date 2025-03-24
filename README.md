# Windows İşlem Yöneticisi

Windows sistemlerde çalışan işlemleri gösterir, yönetir ve analiz eder. Bu uygulama, sistemde çalışan işlemlerin bellek kullanımını, CPU kullanımını, başlangıç zamanını ve diğer önemli bilgileri görüntülemenizi sağlar.

## Özellikler

- İşlemleri bellek kullanımı, CPU kullanımı, isim veya PID'ye göre sıralama
- İşlem sonlandırma
- İşlem önceliği değiştirme
- İşlem detaylarını görüntüleme (başlangıç zamanı, komut satırı, kullanıcı bilgisi, vb.)
- İşlemleri isim, kullanıcı, minimum bellek kullanımı veya CPU kullanımına göre filtreleme

## Gereksinimler

- Windows 7 veya daha yeni
- C++ derleyici (MSVC önerilir)
- CMake 3.10 veya daha yeni

## Derleme

Bu projeyi derlemek için CMake kullanın:

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## Kullanım

Uygulamayı çalıştırdıktan sonra, aşağıdaki menü seçenekleriyle işlemleri yönetebilirsiniz:

1. Çalışan işlemleri listele
2. İşlem sonlandır
3. İşlem önceliği değiştir
4. İşlem detaylarını göster
5. İşlemleri filtrele ve sırala
6. Çıkış

## Notlar

- Bazı işlemlere erişim veya bu işlemleri değiştirmek için yönetici hakları gerekebilir.
- Gerçek Zamanlı (Realtime) işlem önceliği, sistem kararlılığını etkileyebilir, bu nedenle dikkatli kullanılmalıdır.