# PRIVA-FISC - Yazılım Tasarım Dokümanı v0.5

**Tarih:** 12.11.2026, **Yerine geçtiği sürüm:** v0.4 (Ağustos 2026), **Dayanak:** bu depoda çalışan kod ve bu makinede yapılan ölçümler. Ölçülmemiş her şey açıkça "ölçülmedi" diye işaretlidir.

## 0. v0.4'ten bu yana değişen üç şey

| Konu | v0.4 | v0.5 | Neden |
|---|---|---|---|
| Kanıt hattı | Cairo + S-two, üç ayrı devre | Noir devreleri, Barretenberg (UltraHonk) kanıtı, Starknet'te Garaga doğrulayıcı | `scarb prove` çıktısı gizlilik sağlamıyor ve "soundness not yet guaranteed" uyarısı taşıyor; keyfi bir Cairo programının S-two kanıtını doğrulayan Starknet sözleşmesi yok; Cairo'da SHA-256 hazır bileşen değil. Noir hattı bugün uçtan uca çalışıyor. |
| Devlet imzasının kapsamı | "Devlet imzası faturayı bağlar" varsayımı | Devlet imzası yalnız (RequestUUID, SendDateTime, UUID, FIC) dörtlüsünü bağlıyor | Canlı şema ve gerçek imzalı örnek üzerinde doğrulandı. İçerik ve sıra numarası yalnız mükellef imzalı istekte. |
| Devre yapısı | İmza / tamlık / predikat ayrı devreler, sonra birleştirme | Tek ifade: imza + bağ + tamlık + eşik aynı devrede | Fatura başına doğrudan denetim (~0,42 milyon kapı) bir iç kanıtı doğrulamaktan (~0,73 milyon kapı) ucuz. Özyineleme yalnız ölçek için gerekli. |

S-two ve STRK20, Starknet'e yol haritası olarak anlatılır; bugünkü teslimatın parçası değildir.

## 1. Ne kanıtlanıyor, ne kanıtlanmıyor

**Kanıtlanan ifade** (K fatura, tek mükellef anahtarı T, tek idare anahtarı A):

1. Her fatura isteği T ile imzalı ve şu alanları taşıyor: UUID, iş birimi kodu, cihaz (ENU) kodu, sıra numarası, düzenleme yılı, toplam tutar.
2. Her faturanın bir idare yanıtı var, A ile imzalı, ve yanıttaki RequestUUID isteğin UUID'sine eşit.
3. Bütün faturalar aynı iş birimi ve aynı cihazdan; hepsinin yılı açıklanan yıla eşit.
4. Sıra numaraları ardışık (grup içinde boşluk yok).
5. Hiçbir idare yanıtı iki kez kullanılmamış (FIC'ler birbirinden farklı).
6. Tutarların toplamı (düzeltme faturaları eksi sayılır) açıklanan eşikten büyük ya da eşit.

**Açığa çıkan:** T'nin özeti, A'nın özeti, yıl, eşik, fatura sayısı, grubun 1 numaradan başlayıp başlamadığı, fatura başına bir nullifier ve bir açma taahhüdü. **Açığa çıkmayan:** fatura içerikleri, tutarlar, müşteriler, IIC, FIC, sıra numaraları.

**Kanıtlanmayan** (ifadenin gösterildiği her yerde yazılır):

- İdarenin fatura *içeriğini* gördüğü. İdare imzası içeriği kapsamıyor. Ucuz faturalar kaydedip aynı UUID'ler altında başka içerik imzalayan bir mükellef bu devreden geçer. Karşılığı devre dışındadır (bkz. 4.4).
- Son sıra numarasından sonra fatura kesilmediği ve mükellefin başka cihazlarının olmadığı.
- Faturanın gerçek bir satışa karşılık geldiği ya da ödendiği.

Dış iletişimde iddia "kayıt ile kanıt arasındaki tutarlılık"tır; "devlet doğruladı, doğrudur" denmez.

## 2. Güven ve tehdit modeli

Saldırgan kanıtı üreten mükelleftir. Doğrulayıcı (banka, faktoring şirketi, kamu ödeyicisi) şunlara güvenir: idarenin imza anahtarına, kanıt sistemine, ve aşağıdaki denetimlerin devrede gerçekten yapıldığına.

| Saldırı | Karşılık | Nerede |
|---|---|---|
| Sahte idare yanıtı | RSA-2048 imzası devrede doğrulanır; anahtar özeti açık çıktıdır, kayıtlı anahtarla karşılaştırılır | Devre + anahtar kaydı |
| İmzalı belgeyi farklı okutmak (kanonikleştirme oyunu) | Devre belge baytı kabul etmez; yanıtı sabit şablondan kendisi kurar, istekte her alanı tek anlamlı okur | Devre |
| Fatura atlamak | Sıra numaraları ardışık olmak zorunda | Devre |
| Bir yanıtı iki faturaya kullanmak | FIC'ler ikişer ikişer farklı | Devre |
| Tutarı değiştirmek | Tutar mükellef imzalı belgeden okunur; imza bozulur | Devre |
| Aynı faturaları aynı doğrulayıcıya iki kez sunmak | Fatura başına nullifier; doğrulayıcı tekrarı görür | Devre + durum sözleşmesi |
| İçeriği baştan sahte imzalamak | Örnek açtırma: doğrulayıcı rastgele faturalar seçer, açılanları idarenin kamu servisiyle karşılaştırır | Protokol (devre dışı) |

## 3. Bileşenler: nerede ne kullanılıyor

| Parça (v0.4 adı) | Görevi | Araç | Nerede çalışır | Durum |
|---|---|---|---|---|
| ingest-adapter | İmzalı XML'i oku, imzayı ön-denetle | Python (`tools/efi/`) | Mükellefin makinesi | Çalışıyor |
| preprocess-c14n | Kanonik baytları üret | Python + lxml | Mükellefin makinesi | Çalışıyor; devre buna güvenmiyor |
| circuit-sigcore | İki imzanın doğrulanması | Noir: `pf_xmldsig`, `pf_efi` | Mükellefin makinesi | Çalışıyor |
| circuit-completeness | Ardışık sıra, tek kullanım | Noir: `pf_efi/batch.nr` | Mükellefin makinesi | Çalışıyor |
| circuit-predicate | Toplam ≥ eşik | Noir: `pf_efi/batch.nr` | Mükellefin makinesi | Çalışıyor |
| commit | Nullifier ve açma taahhütleri | Noir (Poseidon2) | Mükellefin makinesi | Çalışıyor |
| kanıt üretimi | Kanıtı çıkar | `tools/pf.py prove` -> Barretenberg 6.0.0, `-t evm` (gizlilik kipi); tanık dosyaları silinir | Mükellefin makinesi | Çalışıyor |
| agg-orchestrator | Büyük kümeleri parçalayıp birleştir | Noir özyineleme: yaprak `agg_leaf_*`, kök `pf_agg` + `agg_root_*`; `tools/efi/agg.py` | Mükellefin makinesi | İki yaprak -> bir kök çalışıyor; daha derin ağaç yazılmadı |
| verifier-offline | Kanıtı zincirsiz doğrula | `tools/pf.py verify`: doğrulama anahtarını depodaki devreden kendisi türetir, kanıtı denetler, idare anahtarını `registry/issuer_keys.json` içinde arar | Doğrulayıcının makinesi | Çalışıyor |
| verifier-onchain | Kanıtı Starknet'te doğrula | Garaga'nın ürettiği Cairo sözleşmesi (`starknet/pf_batch_k10_verifier`) | Starknet | Yerel Starknet ağında gerçek işlemle çalışıyor; Sepolia'ya yüklenmedi |
| status-contract | Nullifier defteri, idare anahtar kaydı, kanıtlananın kaydı | Cairo (`starknet/pf_registry`) | Starknet | Testler 6/6; yerel Starknet ağında uçtan uca çalışıyor (`tools/starknet/devnet_demo.sh`); Sepolia'ya yüklenmedi |
| anahtar kaydı | İdare sertifikasından anahtar özeti | `tools/efi/keyhash.py` + Noir `rsa_key_hash`; `registry/issuer_keys.json` | Herkes hesaplayabilir | Çalışıyor; kayıtta yalnız 2021 test sertifikası var |
| örnek açtırma | Seçilen faturayı aç ve karşılaştır | Noir `open_invoice` + `tools/efi/opening.py` | Doğrulayıcı ile mükellef arasında | Açma ve taahhüt denetimi çalışıyor; idare servisiyle karşılaştırma adımı araca bağlanmadı |

Sabit sürümler: Noir 1.0.0, Barretenberg 6.0.0, Scarb/Cairo 2.21.0, Starknet Foundry 0.64.1, Garaga `d97b4d3` (bkz. `tools/toolchain.env`). Korpus mükellefin makinesinden çıkmaz; dışarı yalnız kanıt ve açık çıktılar gider.

## 4. Devre tasarımı

### 4.1 İdare yanıtı (`pf_efi/response.nr`)
Kanonik yanıt sabit düzenli 318 bayttır: dört alan (üç UUID, bir tarih-saat) ve aralarında sabit metin. Devre bu baytları dışarıdan almaz; dört alanı karakter karakter denetler, belgeyi şablondan kendisi kurar, SHA-256 özetini alır, bu özeti yine sabit şablonlu SignedInfo'ya yerleştirir, onun özetini RSA ile doğrular. Sonuç: kanıt varsa idare tam olarak bu dört alanı imzalamıştır. Dışarıdaki kanonikleştirme hatalıysa kanıt üretilemez, ama yanlış bir şey kanıtlanamaz.

### 4.2 Mükellef isteği (`pf_efi/request.nr`)
İstek değişken uzunluktadır (kalemler, alıcı bilgisi). Başlık sabit şablona uydurulur; böylece UUID ve `<Invoice` etiketinin başı sabit konumdadır. Etiketin içi tek geçişte taranır: devre her baytta "tırnak içinde miyim" ve "etiket hâlâ açık mı" durumunu izler ve bir özniteliği yalnız tırnak dışında başlayan ` Ad="` kalıbında tanır. Kanonik XML değerin içinde ham tırnak bırakmadığı için serbest metne yazılmış sahte bir `TotPrice="..."` öznitelik sayılamaz. Aranan yedi öznitelikten her biri tam bir kez geçmek zorundadır. Belgenin geri kalanı yalnız özetlenir.

### 4.3 Toplu ifade (`pf_efi/batch.nr`)
K fatura için 4.1 ve 4.2 çalışır, ardından Bölüm 1'deki altı koşul denetlenir.

- **Nullifier** = Poseidon2(alan etiketi, bağlam, IICSignature özeti). Bağlam doğrulayıcıya özeldir; aynı fatura iki ayrı doğrulayıcıda ilişkilendirilemez. IICSignature seçildi çünkü IIC ve FIC faturanın üstünde basılıdır; onlardan türetilen bir değeri faturanın alıcısı da hesaplayabilirdi.
- **Açma taahhüdü** = Poseidon2(alan etiketi, IIC, FIC, sıra, tarih, tutar, tuz). 4.4'teki denetim için.

### 4.4 İçerik bağı: örnek açtırma (devre dışı protokol)
Doğrulayıcı kanıtı gördükten sonra rastgele birkaç fatura seçer. Mükellef o faturaların açma taahhüdünün içini verir. Doğrulayıcı taahhüdü yeniden hesaplar (`open_invoice`), sonra idarenin kamuya açık fatura sorgu servisine IIC ile sorar ve FIC, tutar ve sıra numarasını karşılaştırır. Açılmayan faturalar gizli kalır. Sahte içerik oranı f ise k fatura açıldığında yakalanma olasılığı 1 − (1 − f)^k'dir; faturaların yarısı sahteyse beş açma %97 yakalar. Kalıcı çözüm idarenin yanıta IIC'yi eklemesidir (tek öznitelik); bu bir politika önerisidir, yazılım işi değildir.

### 4.5 Birleştirme: yaprak ve kök (`pf_efi/agg.nr`, `pf_agg`)
Tek devreye sığmayan kümeler sıra numarasına göre 10'luk yapraklara bölünür. Her yaprak kanıtı kendi 10 faturasını 4.3'teki gibi denetler ama dışarıya yalnız özetinin tuzlanmış taahhüdünü verir (ilk ve son sıra, birim, cihaz, ara toplamlar). Kök kanıt yaprak kanıtlarını kendi içinde doğrular, özetleri açar ve yalnız yapraklar arasında görülebilen üç şeyi denetler: bir yaprağın bittiği sıradan sonrakinin başlaması, aynı birim ve cihaz, genel toplamın eşiği geçmesi.

"Hiçbir yanıt iki kez kullanılmadı" koşulu yapraklar arasında şöyle denetlenir: kanıtlayan köke bütün yanıt kodlarının kesin artan sıralı listesini verir (kesin artan olduğu için tekrarsızdır). Kök, bu listeyle yapraklardaki kodların aynı çoklu-küme olduğunu rastgele bir γ noktasında iki çarpımı karşılaştırarak denetler: yaprakların ∏(γ − kod) çarpımı ile sıralı listenin ∏(γ − kod) çarpımı. γ'yı kanıtlayan seçemez; iki listenin taahhütlerinin özetidir ve kök onu yeniden hesaplar. Kök kanıtın açık değerlerinden biri yaprak devresinin anahtar özetidir; doğrulayıcı bunu güvendiği yaprak devresinin özetiyle karşılaştırmak zorundadır, araç bunu kendisi yapar.

### 4.6 Ölçümler (Apple M3, 16 GB; başka işler çalışırken)

| Devre | Kapı | Kanıt süresi | Bellek | Kanıt boyu | Starknet doğrulama (yerel) |
|---|---|---|---|---|---|
| İdare yanıtı tek başına | 95.575 | 0,7 sn | 0,3 GB | 9,2 KB | geçti, ~178 M l2_gas |
| Mükellef isteği tek başına (≤4096 bayt) | 470.491 | ~3 sn | 1,1 GB | 9,9 KB | ölçülmedi |
| 1 fatura uçtan uca, gerçek 2021 test çifti | 417.256 | 5,0 sn | 0,9 GB | 9,9 KB | geçti, ~186 M l2_gas |
| 10 fatura tek kanıt (sentetik zincir) | 4.086.980 | 22,6 sn | 6,6 GB | 11,1 KB | geçti, ~198 M l2_gas |
| 20 fatura: iki 10'luk yaprak + kök (sentetik zincir) | yaprak 4.088.059, kök 1.470.543 | uçtan uca 99 sn | 4,0 GB | 10,7 KB | ölçülmedi |

10 faturalık devre 2^22 = 4.194.304 kapı sınırının %2,6 altındadır; sınır aşılırsa süre ve bellek ikiye katlanır, bu yüzden istek boyu (2048 bayt) ve etiket penceresi (1280 bayt) bu devrede sabit tutulur. Devrenin derlenmesi yaklaşık 4 dakika, tanık üretimi 7 saniye sürer. Yerel Starknet ağında (starknet-devnet 0.10.1) gerçek bir işlem olarak sunulan 10'luk kanıt kabul edildi: 864 M l2_gas, ağın varsayılan fiyatıyla 0,86 STRK; aynı kanıtın ikinci sunumu "invoice already presented" ile reddedildi. Bu tek işlem büyüktür; Sepolia'daki işlem başına gaz sınırına sığıp sığmadığı ve gerçek ücret ölçülmedi, sığmazsa doğrulama ile kayıt iki işleme bölünür.

## 5. Veri akışı

1. Fatura programı her fatura için idareye bir istek gönderir, imzalı bir yanıt alır. Mükellef bu iki dosyayı saklar.
2. `tools/efi/batch_inputs.py` dosyaları okur, imzaları ön-denetler, devre girdisini yazar. Hiçbir kimlik ya da tutar ekrana basılmaz.
3. Noir devresi çalıştırılır; Barretenberg kanıtı üretir.
4. Mükellef doğrulayıcıya kanıtı ve açık çıktıları verir.
5. Doğrulayıcı kanıtı ya kendi makinesinde ya da Starknet sözleşmesinde doğrular; idare anahtar özetini kayıtlı anahtarla karşılaştırır; nullifier'ları defterde arar.
6. Doğrulayıcı örnek açtırır (4.4).
7. İstisna hâlinde (uyuşmazlık, denetim) mükellef ilgili belgeleri açar.

## 6. Karar kaydı

| Karar | Sonuç | Gerekçe |
|---|---|---|
| TUNE-1 RSA yolu | Noir (`noir_rsa` + `noir-bignum`), anahtar özetiyle | Ölçüldü, çalışıyor. Cairo'daki RSA modülü de Noir kütüphanesi de bağımsız denetimden geçmemiş; denetim açık iş. |
| TUNE-6 Kanonikleştirme | Devre dışında yapılır, devre güvenmez | Şablon yöntemi (4.1) ve tek anlamlı okuma (4.2) |
| TUNE-7 Nullifier | Fatura başına, doğrulayıcıya özel bağlamla | Faktoringde çifte temliki yakalar, doğrulayıcılar arası ilişkilendirmeyi engeller |
| TUNE-9 Gizlilik kipi | Barretenberg'in gizlilik sağlayan kipi kullanılıyor | Dış iletişimde yine "minimum ifşa" denir: neyin açığa çıktığı Bölüm 1'de sayılıdır ve kütüphaneler denetimsizdir |
| Demo boyutu | Tek devre, 10 fatura | Özyinelemesiz en ucuz yol |
| Zincir | Starknet, Garaga doğrulayıcı + Cairo durum sözleşmesi | Çalışan tek zincir-üstü yol |

## 7. Sınırlar ve açık işler

- **Üretim sertifikası bilinmiyor.** Eldeki gerçek örnek 2021 test ortamından. Güncel idare sertifikası ve bir üretim çifti gerekiyor; test ortamına kendi erişimimiz için başvuru yapıldı.
- **Okunamayan biçimler:** saat dilimi "Z" ile biten tarihler, başlığında SubseqDelivType olan istekler, 2048 bayttan uzun istekler (ayar), 1280 bayttan uzun `<Invoice` etiketi. Bunlarda kanıt üretilemez; yanlış kanıt çıkmaz.
- **Henüz okunmayan alanlar:** satıcı vergi numarası, fatura tipi, düzeltme faturasının hangi faturayı düzelttiği.
- **Ölçek:** bugün çalışan en büyük küme 20 faturadır (iki yaprak, bir kök; 4.5). Bir yaprak kanıtını kök içinde doğrulamak yaklaşık 0,70 milyon kapı tutar, bu yüzden tek kök en çok beş yaprağı (50 fatura) kaldırır. Daha büyük kümeler için kökün kendi türünden kanıtları da doğrulayabildiği çok katlı ağaç ve sıralı listenin de parçalanması gerekir; yazılmadı. Kaba hesap: 100 fatura birkaç dakika, 10.000 fatura bu dizüstünde art arda 10 saatin üzerinde (paralelleştirilebilir, fatura kesildikçe de üretilebilir). Not: iç kanıt denetimi tanık üretiminde değil kanıt üretiminde yapılır; birleştirme testleri bu yüzden hep kanıt üretip doğrular.
- **Portaldan kesilen faturalar:** idarenin kendi portalından kesilen faturalarda mükellefin elinde imzalı dosya oluşmaz; bu faturalar kapsam dışıdır.
- **Denetim:** devreler ve kullanılan kütüphaneler bağımsız incelemeden geçmedi.

## 8. Test durumu

Depoda yalnız sentetik veri vardır; gerçek örneklerle denemeler depo dışında yapılır.

| Hedef | Test | Sonuç |
|---|---|---|
| `pf_xmldsig` | Birim testleri (base64, UUID, tarih, tutar, kod) | 13/13 |
| `pf_efi` | İstek okuyucu: sahte öznitelik, tekrar, eksik, kapanmayan etiket | 7/7 |
| İdare yanıtı | Kabul/ret: sahte imza, yanlış anahtar, bozuk alan | 7/7 |
| Mükellef isteği | Kabul/ret + "tutar gibi görünen metin" fark testi | 9/9 |
| 1 fatura | Kabul/ret: kopuk bağ, eşik altı, yanlış yıl, sahte imzalar, tutar değişikliği | 8/8 |
| 10 fatura | Kabul/ret: boşluk, yanıtın iki kez kullanımı, karışık birim/cihaz ve yukarıdakiler | 12/12 |
| Örnek açtırma | Doğru açma eşleşir; tutarı, sırayı ya da FIC'i değiştirilmiş açma eşleşmez | 4/4 |
| Birleştirme (1'lik yapraklar) | Kanıt üreterek: geçerli; yanıtın iki yaprakta kullanımı; bunu sahte sıralı listeyle gizleme; yapraklar arası boşluk; başka cihaz; eşik altı; başka denetim değeriyle kanıtlanmış yaprak; sonradan değiştirilmiş özet; yanlış yaprak devresi özeti | 9/9 |
| Birleştirme (10'luk yapraklar) | Kanıt üreterek: geçerli 20 fatura; yanıtın iki yaprakta kullanımı; sahte sıralı liste | 3/3 |
| Starknet defteri | Gerçek 10 faturalık kanıtla: kayıt, aynı faturaların ikinci sunumu, kayıtsız/kaldırılmış idare anahtarı, yalnız sahip anahtar ekler, değiştirilmiş kanıt | 6/6 |
| Yerel ağda uçtan uca | Yükle -> kur -> idare anahtarını kaydet -> 10'luk kanıtı sun -> kaydı oku -> aynı kanıtı yeniden sun (reddedilir); tek komut, 51 sn | geçti |
| Uçtan uca araç | Gerçek 2021 çiftinde `prove` -> `verify`: geçerli, idare anahtarı kayıtlı; sentetik 10'lukta geçerli ama "anahtar kayıtsız" uyarısı; değiştirilmiş açık değerde geçersiz | elle koşuldu |

## 9. Sıradaki adımlar

1. Doğrulayıcı ve defter sözleşmesini Starknet Sepolia'ya yüklemek ve tek işlemin gaz sınırına sığıp sığmadığını ölçmek.
2. Test ortamından kendi kestiğimiz 10 ardışık gerçek faturayla demo.
3. Örnek açtırmada idarenin kamu servisiyle karşılaştırma adımı.
4. Eksik alanlar ve biçimler (Bölüm 7).
5. 50'den büyük kümeler için çok katlı ağaç; birleştirilmiş kanıtın Starknet doğrulayıcısı.
6. Bağımsız inceleme.
