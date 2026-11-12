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
| agg-orchestrator | Büyük kümeleri parçalayıp birleştir | Noir özyineleme: yaprak `agg_leaf_*`, birleştirici `agg_node`, sıralı liste `agg_sorted_s4096`, üst kanıt `agg_top` (`pf_agg`); `tools/pf.py`, `tools/efi/agg.py` | Mükellefin makinesi | Çalışıyor: 1'den 4096'ya kadar her sayıda fatura; son yaprak kısmen dolu olabilir |
| verifier-offline | Kanıtı zincirsiz doğrula | `tools/pf.py verify`: doğrulama anahtarını depodaki devreden kendisi türetir, kanıtı denetler, idare anahtarını `registry/issuer_keys.json` içinde arar; `--taxpayer-cert` ile kanıttaki mükellef anahtarının verilen sertifikanın anahtarı olduğunu denetler | Doğrulayıcının makinesi | Çalışıyor |
| verifier-onchain | Kanıtı Starknet'te doğrula | Garaga'nın ürettiği iki Cairo sözleşmesi: 10'luk kanıt için `pf_batch_k10_verifier`, birleştirilmiş kanıt için `pf_agg_top_verifier` | Starknet | Yerel Starknet ağında gerçek işlemle çalışıyor; Sepolia'ya yüklenmedi |
| status-contract | Nullifier defteri, idare anahtar kaydı, kanıtlananın kaydı; iki kanıt türünü de kabul eder; birleştirilmiş kanıtta yaprak, birleştirici ve sıralı liste devrelerinin özetlerini kendi kaydıyla karşılaştırır, fatura sayısını kanıttan okur | Cairo (`starknet/pf_registry`) | Starknet | Testler 13/13; yerel Starknet ağında uçtan uca çalışıyor (`tools/starknet/devnet_demo.sh`); Sepolia'ya yüklenmedi |
| anahtar kaydı | İdare sertifikasından anahtar özeti | `tools/efi/keyhash.py` + Noir `rsa_key_hash`; `registry/issuer_keys.json` | Herkes hesaplayabilir | Çalışıyor; kayıtta yalnız 2021 test sertifikası var |
| örnek açtırma | Seçilen faturayı aç ve karşılaştır | `tools/efi/opening.py` (özet hesabı Python'da, `tools/efi/poseidon2.py`; devrelerle karşılaştırmalı testi var) | Doğrulayıcı ile mükellef arasında | Açma ve taahhüt denetimi iki kanıt türünde de çalışıyor; idare servisiyle karşılaştırma adımı araca bağlanmadı |

Sabit sürümler: Noir 1.0.0, Barretenberg 6.0.0, Scarb/Cairo 2.21.0, Starknet Foundry 0.64.1, Garaga `d97b4d3` (bkz. `tools/toolchain.env`). Korpus mükellefin makinesinden çıkmaz; dışarı yalnız kanıt ve açık çıktılar gider.

## 4. Devre tasarımı

### 4.1 İdare yanıtı (`pf_efi/response.nr`)
Kanonik yanıt sabit düzenli 318 bayttır: dört alan (üç UUID, bir tarih-saat) ve aralarında sabit metin. Devre bu baytları dışarıdan almaz; dört alanı karakter karakter denetler, belgeyi şablondan kendisi kurar, SHA-256 özetini alır, bu özeti yine sabit şablonlu SignedInfo'ya yerleştirir, onun özetini RSA ile doğrular. Sonuç: kanıt varsa idare tam olarak bu dört alanı imzalamıştır. Dışarıdaki kanonikleştirme hatalıysa kanıt üretilemez, ama yanlış bir şey kanıtlanamaz. SignedInfo'nun ilk 512 baytı her mesajda aynı olduğu için bu kısmın özet durumu devreye sabit olarak gömülüdür; devre yalnız son üç bloğu özetler (birim testi düz özetle karşılaştırır).

### 4.2 Mükellef isteği (`pf_efi/request.nr`)
İstek değişken uzunluktadır (kalemler, alıcı bilgisi). Başlık sabit şablona uydurulur; böylece UUID ve `<Invoice` etiketinin başı sabit konumdadır. Etiketin içi tek geçişte taranır: devre her baytta "tırnak içinde miyim" ve "etiket hâlâ açık mı" durumunu izler ve bir özniteliği yalnız tırnak dışında başlayan ` Ad="` kalıbında tanır. Kanonik XML değerin içinde ham tırnak bırakmadığı için serbest metne yazılmış sahte bir `TotPrice="..."` öznitelik sayılamaz. Aranan yedi öznitelikten her biri tam bir kez geçmek zorundadır. Belgenin geri kalanı yalnız özetlenir. Etiket düzeyinde tek tırnak reddedilir: kanonik XML değerleri yalnız çift tırnakla sınırlar, bu kural devrenin okuyuşuyla bir XML ayrıştırıcının okuyuşunun ayrışabileceği belgeleri dışarıda bırakır.

### 4.3 Toplu ifade (`pf_efi/batch.nr`)
K fatura için 4.1 ve 4.2 çalışır, ardından Bölüm 1'deki altı koşul denetlenir.

- **Nullifier** = Poseidon2(alan etiketi, bağlam, IICSignature özeti). Bağlam doğrulayıcıya özeldir; aynı fatura iki ayrı doğrulayıcıda ilişkilendirilemez. IICSignature seçildi çünkü IIC ve FIC faturanın üstünde basılıdır; onlardan türetilen bir değeri faturanın alıcısı da hesaplayabilirdi.
- **Açma taahhüdü** = Poseidon2(alan etiketi, IIC, FIC, sıra, tarih, tutar, tuz). 4.4'teki denetim için.

### 4.4 İçerik bağı: örnek açtırma (devre dışı protokol)
Doğrulayıcı kanıtı gördükten sonra rastgele birkaç fatura seçer. Mükellef o faturaların açma taahhüdünün içini verir. Doğrulayıcı taahhüdü yeniden hesaplar (`opening.py check`; bunun için Noir araç zinciri gerekmez), sonra idarenin kamuya açık fatura sorgu servisine IIC ile sorar ve FIC, tutar ve sıra numarasını karşılaştırır. Açılmayan faturalar gizli kalır. Sahte içerik oranı f ise k fatura açıldığında yakalanma olasılığı 1 − (1 − f)^k'dir; faturaların yarısı sahteyse beş açma %97 yakalar. Kalıcı çözüm idarenin yanıta IIC'yi eklemesidir (tek öznitelik); bu bir politika önerisidir, yazılım işi değildir.

10'luk kanıt her faturanın açma taahhüdünü ayrı ayrı yayımlar. Birleştirilmiş kanıt bunların hepsi üzerinde tek bir kök yayımlar; mükellef açtığı faturayla birlikte o yaprağın diğer taahhütlerini ve köke kadar olan kardeş özetleri verir, doğrulayıcı kökü yeniden hesaplar ve açılan faturanın istediği sıra numarasını taşıdığına bakar. Mükellef bunu yapabilmek için kanıtı üretirken kendisinde kalan bir kayıt dosyası saklar (`pf.py prove --keep`). Bu dosya fatura bilgisi içerir, kimseye verilmez; saklanmazsa kanıt sonradan örnekle denetlenemez.

### 4.5 Birleştirme: yaprak, birleştirici, üst kanıt (`pf_efi/agg.nr`, `pf_agg`)
Tek devreye sığmayan kümeler sıra numarasına göre en çok 10 faturalık yapraklara bölünür. Yaprak devresinin 10 yuvası vardır; gizli bir sayı (`count`) ilk kaç yuvanın ifadeye dahil olduğunu söyler. Kalan yuvalarda da geçerli imzalı çiftler bulunmalıdır (kanıtlayan kendi faturalarından birini tekrarlar), ama o yuvalardan okunan hiçbir değer sonuca girmez: sıra denetimine, toplamlara, yanıt kodlarına ve taahhütlere yalnız ilk `count` fatura katılır. Böylece fatura sayısının 10'un katı olması gerekmez. Her yaprak kanıtı kendi faturalarını 4.3'teki gibi denetler ama dışarıya yalnız o dilimin özetinin tuzlanmış taahhüdünü verir (fatura sayısı, ilk ve son sıra, birim, cihaz, ara toplamlar). Birleştirici kanıt komşu iki dilimin kanıtını kendi içinde doğrular, özetleri açar, sağdaki dilimin soldakinin bittiği sıradan başladığını ve birim ile cihazın aynı olduğunu denetler, birleşik dilimin taahhüdünü verir. Çocuk kanıt yaprak da olabilir başka bir birleştirici de; böylece yapraklar ikişer ikişer tek kanıta iner. Üst kanıt bütün dilimin kanıtını ve sıralı liste kanıtını doğrular, genel toplamı eşikle karşılaştırır ve sonucu açıklar.

"Hiçbir yanıt iki kez kullanılmadı" koşulu şöyle denetlenir: kanıtlayan, bütün yanıt kodlarının kesin artan sıralı listesi için ayrı bir kanıt üretir (kesin artan olduğu için tekrarsızdır). Üst kanıt, bu listeyle yapraklardaki kodların aynı çoklu-küme olduğunu rastgele bir γ noktasında iki çarpımı karşılaştırarak denetler: yapraklardan gelen ∏(γ − kod) ile sıralı listenin ∏(γ − kod) çarpımı. γ'yı kanıtlayan seçemez; iki listenin taahhütlerinin özetidir ve üst kanıt onu yeniden hesaplar. Üst kanıtın açık değerleri arasında yaprak, birleştirici ve sıralı liste devrelerinin anahtar özetleri vardır; doğrulayıcı bunları güvendiği devrelerin özetleriyle karşılaştırmak zorundadır, araç ve defter sözleşmesi bunu kendisi yapar.

### 4.6 Ölçümler (Apple M3, 16 GB; başka işler çalışırken)

| Devre | Kapı | Kanıt süresi | Bellek | Kanıt boyu | Starknet doğrulama (yerel) |
|---|---|---|---|---|---|
| İdare yanıtı tek başına | 60.985 | 0,5 sn | 0,2 GB | 9,2 KB | ölçülmedi |
| Mükellef isteği tek başına (≤4096 bayt) | 421.416 | ~3 sn | 1,1 GB | 9,9 KB | ölçülmedi |
| 1 fatura uçtan uca, gerçek 2021 test çifti | 333.179 | 2,4 sn | 0,8 GB | 9,9 KB | ölçülmedi |
| 10 fatura tek kanıt (sentetik zincir) | 3.243.085 | 19 sn | 5,7 GB | 11,1 KB | geçti |
| 3 fatura: kısmen dolu tek yaprak, sıralı liste, üst kanıt | yaprak 3.244.701; üst 1.469.068; sıralı liste (4096 kod) 255.262 | uçtan uca 57 sn | yaprak başına 5,7 GB | 10,7 KB | ölçülmedi |
| 13 fatura: iki yaprak (10 + 3), bir birleştirici, sıralı liste, üst kanıt | aynı devreler; birleştirici 1.469.809 | uçtan uca 95 sn | yaprak başına 5,7 GB | 10,7 KB | ölçülmedi |
| 25 fatura: üç yaprak (10 + 10 + 5), iki birleştirici, sıralı liste, üst kanıt | aynı devreler | uçtan uca 134 sn | yaprak başına 5,7 GB | 10,7 KB | geçti |
| 100 fatura: on yaprak, dokuz birleştirici, sıralı liste, üst kanıt | aynı devreler | uçtan uca 411 sn | yaprak başına 5,7 GB | 10,7 KB | ölçülmedi |

10 faturalık devreler 2^22 = 4.194.304 kapı sınırının yaklaşık %23 altındadır. Fatura başına maliyetin büyük kısmı isteğin özetlenmesi (2048 bayt için yaklaşık 150 bin kapı) ve iki RSA denetimidir; sınır aşılırsa süre ve bellek ikiye katlanır, bu yüzden istek boyu (2048 bayt) ve etiket penceresi (1280 bayt) bu devrede sabit tutulur. Devrenin derlenmesi yaklaşık 4 dakika, tanık üretimi 7 saniye sürer. Yerel Starknet ağında (starknet-devnet 0.10.1) iki kanıt türü de gerçek birer işlemle sunuldu ve kabul edildi: 10'luk kanıt 862 M, 25 faturalık birleştirilmiş kanıt 821 M L2 gaz (ağın varsayılan fiyatıyla 0,86 ve 0,82 STRK). Birleştirilmiş kanıtın zincir maliyeti fatura sayısıyla artmaz. Starknet belgelerindeki işlem başına sınır 1,11 milyar L2 gazdır; iki işlem de bunun altındadır. İkisinin de ikinci sunumu "invoice already presented" ile reddedildi. Açık ağda ölçüm yapılmadı.

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
- **Henüz okunmayan alanlar:** fatura tipi, düzeltme faturasının hangi faturayı düzelttiği.
- **Mükellefin kimliği devrede okunmaz, bilerek.** İstekteki satıcı vergi numarası mükellefin kendi yazdığı bir alandır. Kanıt mükellefi imza anahtarının özetiyle adlandırır; kimlik, sertifika kurumunun onayladığı fiskalizasyon sertifikasından gelir (`pf.py verify --taxpayer-cert`). Sertifikanın kendisinin denetimi (kök, geçerlilik, iptal) olağan X.509 araçlarıyla yapılır.
- **Ölçek:** birleştirilmiş kanıt 1'den 4096'ya kadar her fatura sayısında çalışır (4096, sıralı liste devresinin kapasitesidir; daha büyüğü için listenin de parçalanması gerekir). Süre fatura sayısıyla doğrusal artar: ilk yaprakla birlikte yaklaşık 57 sn, sonraki her 10 fatura için yaklaşık 40 sn. Bu hızla 1.000 fatura bir saatin biraz üstünde, 4.096 fatura dört saatin üstünde sürer; bunlar hesaptır, 100 faturadan büyüğü koşulmadı (100 fatura 411 sn sürdü, hesapla uyumlu). Yapraklar sırayla üretildiği için bellek fatura sayısıyla artmaz; yapraklar birbirinden bağımsızdır, birden çok makineye dağıtılabilir. Not: iç kanıt denetimi tanık üretiminde değil kanıt üretiminde yapılır; birleştirme testleri bu yüzden hep kanıt üretip doğrular.
- **Portaldan kesilen faturalar:** idarenin kendi portalından kesilen faturalarda mükellefin elinde imzalı dosya oluşmaz; bu faturalar kapsam dışıdır.
- **Denetim:** devreler ve kullanılan kütüphaneler bağımsız incelemeden geçmedi.

## 8. Test durumu

Depoda yalnız sentetik veri vardır; gerçek örneklerle denemeler depo dışında yapılır.

| Hedef | Test | Sonuç |
|---|---|---|
| `pf_xmldsig` | Birim testleri (base64, UUID, tarih, tutar, kod, onaltılık tablo, SignedInfo özetinin düz özetle karşılaştırması) | 17/17 |
| `pf_efi` | İstek okuyucu (sahte öznitelik, tekrar, eksik, kapanmayan etiket, tek tırnak), kısmen dolu devrede sayılan ve sayılmayan yuvalar, birleştirme yardımcıları (sıralı liste, dilim birleştirme) | 21/21 |
| İdare yanıtı | Kabul/ret: sahte imza, yanlış anahtar, bozuk alan | 7/7 |
| Mükellef isteği | Kabul/ret + "tutar gibi görünen metin" fark testi | 9/9 |
| 1 fatura | Kabul/ret: kopuk bağ, eşik altı, yanlış yıl, sahte imzalar, tutar değişikliği | 8/8 |
| 10 fatura | Kabul/ret: boşluk, yanıtın iki kez kullanımı, karışık birim/cihaz ve yukarıdakiler | 12/12 |
| Örnek açtırma | Doğru açma eşleşir; tutarı, sırayı ya da FIC'i değiştirilmiş açma eşleşmez | 4/4 |
| Özet fonksiyonu | Araçların Python Poseidon2'si devrelerle karşılaştırılır: referans vektör, 0 ile 10 arası eleman sayıları, açma taahhüdü | 13/13 |
| Birleştirme (1'lik yapraklar) | Kanıt üreterek: 1, 2 ve 3 yapraklı geçerli ağaçlar; yanıtın iki yaprakta kullanımı; bunu baştan sahte sıralı listeyle gizleme; yapraklar arası boşluk; başka cihaz; eşik altı; başka denetim değeriyle kanıtlanmış yaprak; sonradan değiştirilmiş özet; yanlış yaprak devresi özeti; yaprağın birleştirici diye sunulması; tek yuvalı yaprağın iki fatura taşıdığının söylenmesi. Geçerli üç yapraklı kanıtta örnek açtırma: iki fatura açılır, tutarı değiştirilmiş ya da başka yola bağlanmış açma reddedilir | 13/13 ve 4/4 |
| Birleştirme (10'luk yapraklar) | Kanıt üreterek: geçerli 20, 23 (10 + 10 + 3) ve 7 fatura; boş yuvanın fatura sayılması; sıfır ya da 11 fatura taşıdığı söylenen yaprak; yapraklar arasında dört faturanın atlanması; yanıtın iki yaprakta kullanımı ve sahte sıralı liste. 23 ve 7 faturalık kanıtlarda örnek açtırma | 8/8 ve 6/6 |
| Starknet defteri | Gerçek 10'luk ve 20'lik kanıtlarla: kayıt, ikinci sunum, kayıtsız ya da kaldırılmış idare anahtarı, yalnız sahip anahtar ekler, değiştirilmiş kanıt, birleştirilmiş kanıtın 10'luk girişten sunulması, tanınmayan yaprak, birleştirici ya da sıralı liste devresi | 13/13 |
| Yerel ağda uçtan uca | Sözleşmeleri yükle ve kur; 10'luk ve 25 faturalık kanıt için: idare anahtarını kaydet, kanıtı sun, aynı kanıtı yeniden sun (reddedilir). Tek komut, yaklaşık 4 dakika | geçti |
| Uçtan uca araç | Gerçek 2021 çiftinde `prove` -> `verify`: geçerli, idare anahtarı kayıtlı; sentetik 10'lukta geçerli ama "anahtar kayıtsız" uyarısı; değiştirilmiş açık değerde geçersiz; 3, 13, 25 ve 100 sentetik faturayla `prove --keep` -> `verify` -> son faturanın örnek açtırması | elle koşuldu |

## 9. Sıradaki adımlar

1. Doğrulayıcıları ve defter sözleşmesini Starknet Sepolia'ya yüklemek ve gerçek ücreti ölçmek.
2. Test ortamından kendi kestiğimiz 10 ardışık gerçek faturayla demo.
3. Örnek açtırmada idarenin kamu servisiyle karşılaştırma adımı.
4. Eksik alanlar ve biçimler (Bölüm 7).
5. 4096'dan büyük kümeler (sıralı listenin de parçalanması) ve yaprakların birden çok makinede üretilmesi.
6. Bağımsız inceleme.
