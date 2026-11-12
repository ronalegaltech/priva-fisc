# PRIVA-FISC - Yazılım Tasarım Dokümanı v0.5

**Tarih:** 12.11.2026, **Yerine geçtiği sürüm:** v0.4 (Ağustos 2026), **Dayanak:** bu depoda çalışan kod ve bu makinede yapılan ölçümler. Ölçülmemiş her şey açıkça "ölçülmedi" diye işaretlidir.

## 0. v0.4'ten bu yana değişen üç şey

| Konu | v0.4 | v0.5 | Neden |
|---|---|---|---|
| Kanıt hattı | Cairo + S-two, üç ayrı devre | Noir devreleri, Barretenberg (UltraHonk) kanıtı, Starknet'te Garaga doğrulayıcı | `scarb prove` çıktısı gizlilik sağlamıyor ve "soundness not yet guaranteed" uyarısı taşıyor; keyfi bir Cairo programının S-two kanıtını doğrulayan Starknet sözleşmesi yok; Cairo'da SHA-256 hazır bileşen değil. Noir hattı bugün uçtan uca çalışıyor. |
| Devlet imzasının kapsamı | "Devlet imzası faturayı bağlar" varsayımı | Devlet imzası yalnız (RequestUUID, SendDateTime, UUID, FIC) dörtlüsünü bağlıyor | Canlı şema ve gerçek imzalı örnek üzerinde doğrulandı. İçerik ve sıra numarası yalnız mükellef imzalı istekte. |
| Devre yapısı | İmza / tamlık / predikat ayrı devreler, sonra birleştirme | Tek ifade: imza + bağ + tamlık + eşik aynı devrede | Fatura başına doğrudan denetim (~0,34 milyon kapı) bir iç kanıtı doğrulamaktan (~0,73 milyon kapı) ucuz. Özyineleme yalnız ölçek için gerekli. |

S-two ve STRK20, Starknet'e yol haritası olarak anlatılır; bugünkü teslimatın parçası değildir.

## 1. Ne kanıtlanıyor, ne kanıtlanmıyor

**Kanıtlanan ifade** (K fatura, tek mükellef anahtarı T, tek idare anahtarı A):

1. Her fatura isteği T ile imzalı ve şu alanları taşıyor: UUID, iş birimi kodu, cihaz (ENU) kodu, sıra numarası, düzenleme yılı, toplam tutar.
2. Her faturanın bir idare yanıtı var, A ile imzalı; yanıttaki RequestUUID isteğin UUID'sine eşit ve idarenin yanıta koyduğu tarih açıklanan yıla ait (ertesi yılın ilk üç günü de kabul edilir: yılbaşı gecesi kesilen fatura gece yarısından sonra kaydedilebilir).
3. Mükellefin imzaladığı hâliyle bütün faturalar aynı iş birimi ve aynı cihazdan; hepsinin düzenleme yılı açıklanan yıla eşit.
4. Mükellefin imzaladığı sıra numaraları ardışık (grup içinde boşluk yok).
5. Hiçbir idare yanıtı iki kez kullanılmamış (FIC'ler birbirinden farklı).
6. Tutarların toplamı (düzeltme faturaları eksi sayılır) açıklanan eşikten büyük ya da eşit.

**Açığa çıkan:** T'nin özeti, A'nın özeti, yıl, eşik, fatura sayısı, grubun 1 numaradan başlayıp başlamadığı, kanıtın hangi bağlam için üretildiği, fatura başına bir nullifier ve bir açma taahhüdü (birleştirilmiş kanıtta bunların yerine tek bir kapsam nullifier'ı ve açma ağacının kökü). **Açığa çıkmayan:** fatura içerikleri, tutarlar, müşteriler, IIC, FIC. Grup 1 numaradan başlıyorsa fatura sayısı hangi sıra numaralarını kapsadığını da söyler.

**Kanıtlanmayan** (ifadenin gösterildiği her yerde yazılır):

- İdarenin fatura *içeriğini* gördüğü. İdare imzası yalnız istek UUID'sini ve yanıt kodunu kapsıyor. İfadenin istekten aldığı her şey (sıra numarası, yıl, tutar, iş birimi, cihaz) mükellefin kendi imzaladığıdır. Ucuz faturalar kaydedip aynı UUID'ler altında başka içerik imzalayan bir mükellef bu devreden geçer. Karşılığı devre dışındadır (bkz. 4.4).
- Tutarların doğru olduğu. Eşik ifadesinde tek bir şişirilmiş fatura toplamın büyük kısmını taşıyabilir; numarayla birkaç fatura açtırmak bunu kaçırabilir. Birleştirilmiş kanıtta tutarla sorma şişirilmiş faturayı yakalar, tutarı küçültülmüş düzeltme faturasını yakalamaz (bkz. 4.4).
- Son sıra numarasından sonra fatura kesilmediği ve mükellefin başka cihazlarının olmadığı.
- Faturanın gerçek bir satışa karşılık geldiği ya da ödendiği.

Dış iletişimde iddia "kayıt ile kanıt arasındaki tutarlılık"tır; "devlet doğruladı, doğrudur" denmez.

## 2. Güven ve tehdit modeli

Saldırgan kanıtı üreten mükelleftir. Doğrulayıcı (banka, faktoring şirketi, kamu ödeyicisi) şunlara güvenir: idarenin imza anahtarına, kanıt sistemine, ve aşağıdaki denetimlerin devrede gerçekten yapıldığına.

| Saldırı | Karşılık | Nerede |
|---|---|---|
| Sahte idare yanıtı | RSA-2048 imzası devrede doğrulanır; anahtar özeti açık çıktıdır, kayıtlı anahtarla karşılaştırılır | Devre + anahtar kaydı |
| İmzalı belgeyi farklı okutmak (kanonikleştirme oyunu) | Devre belge baytı kabul etmez; yanıtı sabit şablondan kendisi kurar, istekte her alanı tek anlamlı okur | Devre |
| Fatura atlamak | Devre, mükellefin imzaladığı sıra numaralarının ardışık olmasını ister. Bir faturayı atlayan mükellef sonraki bütün faturaları yeniden numaralayıp imzalamak zorundadır; atlanan yerden sonra açılan her fatura idare kaydıyla çelişir | Devre + örnek açtırma |
| Bir yanıtı iki faturaya kullanmak | FIC'ler ikişer ikişer farklı | Devre |
| Tutarı değiştirmek | İmzalandıktan sonra değiştirilen belgede imza bozulur. Mükellef aynı faturayı başka tutarla yeniden imzalarsa devre bunu göremez; açılan fatura idare kaydıyla çelişir | Devre + örnek açtırma |
| Aynı faturaları aynı doğrulayıcıya iki kez sunmak | Fatura başına nullifier, idarenin verdiği yanıt kodundan türetilir; mükellef faturayı yeniden imzalayarak değiştiremez. Doğrulayıcı kendi verdiği bağlamı kanıttakiyle karşılaştırır ve gördüğü nullifier'ları saklar (`pf.py verify --ledger` ya da zincirdeki defter); hafızası olmayan doğrulayıcı tekrarı göremez | Devre + doğrulayıcının defteri ya da durum sözleşmesi |
| Faturayı başka cihaz ya da birim koduyla yeniden imzalamak (cihazları karıştırmak, kapsam nullifier'ını değiştirmek) | Birim ve cihaz açma taahhüdünün içindedir; örnek açtırmada idare kaydıyla karşılaştırılır | Protokol (devre dışı) |
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
| status-contract | Nullifier defteri, idare anahtar kaydı, kanıtlananın kaydı; iki kanıt türünü de kabul eder, bir bağlamda yalnız birini; birleştirilmiş kanıtta yaprak, birleştirici ve sıralı liste devrelerinin özetlerini kendi kaydıyla karşılaştırır, fatura sayısını kanıttan okur | Cairo (`starknet/pf_registry`) | Starknet | Testler 16/16; yerel Starknet ağında uçtan uca çalışıyor (`tools/starknet/devnet_demo.sh`); Sepolia'ya yüklenmedi |
| anahtar kaydı | İdare sertifikasından anahtar özeti | `tools/efi/keyhash.py` + Noir `rsa_key_hash`; `registry/issuer_keys.json` | Herkes hesaplayabilir | Çalışıyor; kayıtta yalnız 2020 tarihli test ortamı sertifikası var |
| örnek açtırma | Seçilen faturayı aç ve karşılaştır; birleştirilmiş kanıtta faturanın kökün altındaki yerini yolu göstermeden kanıtla; numarayla ya da tutar noktasıyla sor | `tools/efi/opening.py`, Noir `spot_open_k*` (`pf_efi/spot.nr`); özet hesabı Python'da (`tools/efi/poseidon2.py`, devrelerle karşılaştırmalı testi var) | Doğrulayıcı ile mükellef arasında | Açma, taahhüt denetimi ve idare kaydıyla alan alan karşılaştırma (`opening.py compare`) çalışıyor; idarenin servisine sorguyu araç yapmaz, doğrulayıcı gördüğünü küçük bir dosyaya yazar |

Sabit sürümler: Noir 1.0.0, Barretenberg 6.0.0, Scarb/Cairo 2.21.0, Starknet Foundry 0.64.1, Garaga `d97b4d3` (bkz. `tools/toolchain.env`). Korpus mükellefin makinesinden çıkmaz; dışarı yalnız kanıt ve açık çıktılar gider.

## 4. Devre tasarımı

### 4.1 İdare yanıtı (`pf_efi/response.nr`)
Kanonik yanıt sabit düzenli 318 bayttır: dört alan (üç UUID, bir tarih-saat) ve aralarında sabit metin. Devre bu baytları dışarıdan almaz; dört alanı karakter karakter denetler, belgeyi şablondan kendisi kurar, SHA-256 özetini alır, bu özeti yine sabit şablonlu SignedInfo'ya yerleştirir, onun özetini RSA ile doğrular. Sonuç: kanıt varsa idare tam olarak bu dört alanı imzalamıştır. Dışarıdaki kanonikleştirme hatalıysa kanıt üretilemez, ama yanlış bir şey kanıtlanamaz. SignedInfo'nun ilk 512 baytı her mesajda aynı olduğu için bu kısmın özet durumu devreye sabit olarak gömülüdür; devre yalnız son üç bloğu özetler (birim testi düz özetle karşılaştırır).

### 4.2 Mükellef isteği (`pf_efi/request.nr`)
İstek değişken uzunluktadır (kalemler, alıcı bilgisi). Başlık sabit şablona uydurulur; böylece UUID ve `<Invoice` etiketinin başı sabit konumdadır. Etiketin içi tek geçişte taranır: devre her baytta "tırnak içinde miyim" ve "etiket hâlâ açık mı" durumunu izler ve bir özniteliği yalnız tırnak dışında başlayan ` Ad="` kalıbında tanır. Kanonik XML değerin içinde ham tırnak bırakmadığı için serbest metne yazılmış sahte bir `TotPrice="..."` öznitelik sayılamaz. Aranan altı öznitelikten her biri tam bir kez geçmek zorundadır. Belgenin geri kalanı yalnız özetlenir. Kanonik XML'de bulunmayan ve bir XML ayrıştırıcının bu taramadan farklı okuyabileceği şeyler etiket düzeyinde reddedilir: tek tırnak (değerler yalnız çift tırnakla sınırlanır), sekme ve satır sonu (öznitelikler tek boşlukla ayrılır), ad alanı bildirimi (` xmlns`; kendi ad alanı olan bir `Invoice` artık EFI faturası değildir). Belge `</Invoice></RegisterInvoiceRequest>` ile bitmek zorundadır. Sayılar tek biçimde okunur: baştaki sıfır, sıfır sıra numarası ve eksi sıfır kabul edilmez; tarihlerde ay, gün ve saat aralık içinde, saat farkı +01:00 ya da +02:00 olmalıdır.

### 4.3 Toplu ifade (`pf_efi/batch.nr`)
K fatura için 4.1 ve 4.2 çalışır, ardından Bölüm 1'deki altı koşul denetlenir.

- **Nullifier** = Poseidon2(alan etiketi, bağlam, FIC). Bağlamı doğrulayıcı seçer ve mükellefe verir; aynı fatura iki ayrı doğrulayıcıda ilişkilendirilemez. FIC seçildi çünkü onu yalnız idare verir: mükellef aynı faturayı başka baytlarla yeniden imzalayabilir ama ona ikinci bir yanıt kodu alamaz. Mükellefin yazdığı herhangi bir alandan (ilk sürümde IICSignature idi) türetilen nullifier yeniden imzalamayla değiştirilebilirdi. Bedeli: FIC faturanın üstünde basılıdır; bir faturanın FIC'ini ve bağlamı bilen kişi o faturanın bir 10'luk kanıtta sunulup sunulmadığını anlayabilir. Birleştirilmiş kanıt fatura başına nullifier yayımlamaz.
- **Açma taahhüdü** = Poseidon2(alan etiketi, IIC, FIC, sıra, tarih, tutar, iş birimi, cihaz, tuz). İfadenin istekten aldığı her alan buradadır; 4.4'teki denetim bunların hepsini kapsar.
- **Kapsam nullifier'ı** (birleştirilmiş kanıt) = Poseidon2(alan etiketi, bağlam, mükellef anahtarının yayımlanmayan ikinci özeti, iş birimi, cihaz, yıl). Aynı dizinin aynı bağlamda ikinci kez sunulmasını durdurur. Yayımlanan anahtar özeti yerine ikinci bir özet kullanılır, çünkü birim ve cihaz kodları faturada basılıdır; yayımlanan özetle hesaplansaydı her müşteri bir kaydın hangi işletmeye ait olduğunu bulabilirdi. Birim ve cihaz mükellefin beyanıdır; doğruluğunu örnek açtırma gösterir.

### 4.4 İçerik bağı: örnek açtırma (devre dışı protokol)
Doğrulayıcı kanıtı gördükten sonra rastgele birkaç fatura seçer. Mükellef o faturaların açma taahhüdünün içini verir. Doğrulayıcı taahhüdü yeniden hesaplar (`opening.py check`), sonra idarenin kamuya açık fatura sorgu servisine IIC ile sorar; yanıt kodunu, sıra numarasını, tarihi, tutarı, iş birimini ve cihazı açılan değerlerle, kayıttaki satıcıyı da mükellefin sertifikasıyla karşılaştırır. Açılmayan faturalar gizli kalır.

Doğrulayıcı önce kanıtın kendisini doğrular (`pf.py verify`; `opening.py check` de bunu kendisi yapar), sonra hangi faturayı istediğini araca kendisi söyler (`--ordinal`, `--first`, `--last`, ya da tutarla sorarken `--seed` ve `--draw`); mükellef istenen yerine başka bir faturayı açamaz. Dizi 1 numaradan başlamıyorsa doğrulayıcı önce ilk faturayı açtırır: onun sıra numarası ve yayımlanan fatura sayısı, diğer numaraların çekileceği aralığı verir. Cevaplanmayan bir istek, gerekçesi ne olursa olsun, başarısız bir örnek açtırmadır; doğrulayıcı yeniden çekiliş yapmaz ve yerine yeni bir kanıt kabul etmez.

Bu denetimin gücü neyin değiştirildiğine ve nasıl sorulduğuna bağlıdır. Numarayla sorulduğunda, faturaların f oranı değiştirilmişse k açma 1 − (1 − f)^k olasılıkla yakalar (yarısı sahteyse beş açma %97). Ama eşik ifadesinde tek bir şişirilmiş fatura eşiğin tamamını taşıyabilir; N fatura içinden k tanesinin numarayla açılması onu yalnız k/N olasılıkla bulur.

Bu yüzden birleştirilmiş kanıtta ikinci bir soru biçimi vardır: **tutarla sorma** (denetçilerin "parasal birim örneklemesi"). Doğrulayıcı rastgele bir tohum üretir (`opening.py draw`); tohum, pozitif tutarların toplamı üzerinde 1, 2, 3 diye numaralı noktalar belirler ve mükellef her nokta için o noktayı kapsayan faturayı açmak zorundadır. Bir faturanın istenme olasılığı tutarının pozitif tutarlar toplamındaki payına eşittir. Bunun verdiği ve vermediği şunlardır. (1) Şişirilmiş faturaları, **brüt** pozitif toplam içindeki payları oranında bulur. Bu toplamı doğrulayıcı görmez ve mükellef onu gerçek bir büyük fatura ile onun gerçek iade faturasıyla büyütebilir: net toplam değişmez, çekilişlerin çoğu gerçek büyük faturaya düşer. Bu yüzden iade faturası bulunabilen bir dizide çekiliş sayısından hesaplanabilir bir güvence çıkmaz. (2) Daha küçük bir tutarla, sıfırla ya da küçük bir fatura olarak yeniden imzalanmış iade faturasını bulmaz; tutarı küçük ya da eksi olduğu için nadiren çekilir ya da hiç çekilmez. Ona karşı yalnız numarayla sorma kalır. (3) Her cevap, açılan faturanın kümülatif toplamın neresinde durduğunu doğrulayıcıya kabaca söyler; cevaplar biriktikçe toplam hakkında bilgi birikir. Noktalar bu yüzden tek bir tohumdan türetilir (doğrulayıcı bir cevabı gördükten sonra nokta seçemez) ve mükellefin aracı kanıt başına tek tohuma, en çok on çekilişe cevap verir.

10'luk kanıt her faturanın açma taahhüdünü ayrı ayrı yayımlar; orada fatura yerine göre sorulur. Birleştirilmiş kanıt bütün açma taahhütleri üzerinde tek bir kök yayımlar. Bu kökün altındaki ağaç her düğümde altındaki pozitif tutarların toplamını da taşır (4.5). Mükellef açtığı faturayla birlikte küçük bir kanıt verir (`spot_open` devresi, yaklaşık 8 bin kapı): taahhüt bu kökün altındadır; ilk fatura mıdır, son fatura mıdır; doğrulayıcının çektiği noktayı kapsar mı. Yolun kendisi (kardeş özetler ve toplamlar, yaprağın diğer taahhütleri) açıklanmaz; genel toplam da yayımlanmaz, ama yukarıda anlatıldığı gibi tutarla verilen cevaplardan kısmen kestirilebilir. Bir açma dosyası devredilebilir bir kanıttır: onu ve yayımlanmış kanıtı elinde tutan herkes denetleyebilir. Mükellef bunu yapabilmek için kanıtı üretirken kendisinde kalan bir kayıt dosyası saklar (`pf.py prove --keep`). Bu dosya fatura bilgisi içerir, kimseye verilmez; saklanmazsa kanıt sonradan örnekle denetlenemez.

Kalıcı çözüm idarenin yanıta IIC'yi eklemesidir (tek öznitelik); bu bir politika önerisidir, yazılım işi değildir.

### 4.5 Birleştirme: yaprak, birleştirici, üst kanıt (`pf_efi/agg.nr`, `pf_agg`)
Tek devreye sığmayan kümeler sıra numarasına göre en çok 10 faturalık yapraklara bölünür. Yaprak devresinin 10 yuvası vardır; gizli bir sayı (`count`) ilk kaç yuvanın ifadeye dahil olduğunu söyler. Kalan yuvalarda da geçerli imzalı çiftler bulunmalıdır (kanıtlayan kendi faturalarından birini tekrarlar), ama o yuvalardan okunan hiçbir değer sonuca girmez: sıra denetimine, toplamlara, yanıt kodlarına ve taahhütlere yalnız ilk `count` fatura katılır. Böylece fatura sayısının 10'un katı olması gerekmez. Her yaprak kanıtı kendi faturalarını 4.3'teki gibi denetler ama dışarıya yalnız o dilimin özetinin tuzlanmış taahhüdünü verir (fatura sayısı, ilk ve son sıra, birim, cihaz, ara toplamlar). Birleştirici kanıt komşu iki dilimin kanıtını kendi içinde doğrular, özetleri açar, sağdaki dilimin soldakinin bittiği sıradan başladığını ve birim ile cihazın aynı olduğunu denetler, birleşik dilimin taahhüdünü verir. Açma taahhütleri tutar taşıyan bir ağaçta tutulur: yaprak kendi taahhütlerine ve pozitif tutarlarına, birleştirici iki çocuğuna ve her birinin altındaki pozitif tutar toplamına bağlanır; üst kanıt bu ağacın kökünü genel toplamla birlikte tek bir değer olarak yayımlar (4.4'teki tutarla sorma bunun üzerinde çalışır). Her dilim özeti kendi derinliğini de taşır; üst kanıt 12 birleştirmeden derin bir ağacı kabul etmez. Kanıtlayan ağaca hangi biçimi verirse versin, geçerli bir birleştirilmiş kanıttaki her fatura örnek açtırma devresinin erişebileceği derinliktedir. Çocuk kanıt yaprak da olabilir başka bir birleştirici de; böylece yapraklar ikişer ikişer tek kanıta iner. Üst kanıt bütün dilimin kanıtını ve sıralı liste kanıtını doğrular, genel toplamı eşikle karşılaştırır ve sonucu açıklar.

"Hiçbir yanıt iki kez kullanılmadı" koşulu şöyle denetlenir: kanıtlayan, bütün yanıt kodlarının kesin artan sıralı listesi için ayrı bir kanıt üretir (kesin artan olduğu için tekrarsızdır). Üst kanıt, bu listeyle yapraklardaki kodların aynı çoklu-küme olduğunu rastgele bir γ noktasında iki çarpımı karşılaştırarak denetler: yapraklardan gelen ∏(γ − kod) ile sıralı listenin ∏(γ − kod) çarpımı. γ'yı kanıtlayan seçemez; iki listenin taahhütlerinin özetidir ve üst kanıt onu yeniden hesaplar. Üst kanıtın açık değerleri arasında yaprak, birleştirici ve sıralı liste devrelerinin anahtar özetleri vardır; doğrulayıcı bunları güvendiği devrelerin özetleriyle karşılaştırmak zorundadır, araç ve defter sözleşmesi bunu kendisi yapar.

### 4.6 Ölçümler (Apple M3, 16 GB; başka işler çalışırken)

| Devre | Kapı | Kanıt süresi | Bellek | Kanıt boyu | Starknet doğrulama (yerel) |
|---|---|---|---|---|---|
| İdare yanıtı tek başına | 60.946 | 0,5 sn | 0,2 GB | 9,2 KB | ölçülmedi |
| Mükellef isteği tek başına (≤4096 bayt) | 429.827 | ~3 sn | 1,1 GB | 9,9 KB | ölçülmedi |
| 1 fatura uçtan uca, gerçek 2021 test çifti | 341.657 | 2-3 sn | 1,0 GB | 9,9 KB | ölçülmedi |
| 10 fatura tek kanıt (sentetik zincir) | 3.327.727 | 20-24 sn | 4-6 GB | 11,1 KB | geçti |
| 3 fatura: kısmen dolu tek yaprak, sıralı liste, üst kanıt | yaprak 3.329.410; üst 1.468.995; sıralı liste (4096 kod) 255.262 | uçtan uca 64 sn | yaprak başına 4-6 GB | 10,7 KB | ölçülmedi |
| 13 fatura: iki yaprak (10 + 3), bir birleştirici, sıralı liste, üst kanıt | aynı devreler; birleştirici 1.469.823 | uçtan uca 104 sn | yaprak başına 4-6 GB | 10,7 KB | ölçülmedi |
| 25 fatura: üç yaprak (10 + 10 + 5), iki birleştirici, sıralı liste, üst kanıt | aynı devreler | uçtan uca 148 sn | yaprak başına 4-6 GB | 10,7 KB | geçti |
| 100 fatura: on yaprak, dokuz birleştirici, sıralı liste, üst kanıt | aynı devreler | uçtan uca 426 sn | yaprak başına 4-6 GB | 10,7 KB | ölçülmedi |
| Örnek açtırma kanıtı (birleştirilmiş kanıtta bir faturanın yeri) | 8.387 | ~1 sn | 0,1 GB altı | açma dosyası 17 KB | zincir dışı |

10 faturalık devreler 2^22 = 4.194.304 kapı sınırının yaklaşık %20 altındadır. Fatura başına maliyetin büyük kısmı isteğin özetlenmesi (2048 bayt için yaklaşık 150 bin kapı) ve iki RSA denetimidir; sınır aşılırsa süre ve bellek ikiye katlanır, bu yüzden istek boyu (2048 bayt) ve etiket penceresi (1280 bayt) bu devrede sabit tutulur. Devrenin derlenmesi yaklaşık 4 dakika, tanık üretimi 7 saniye sürer. Yerel Starknet ağında (starknet-devnet 0.10.1) iki kanıt türü de gerçek birer işlemle sunuldu ve kabul edildi: 10'luk kanıt 865 M, 25 faturalık birleştirilmiş kanıt 822 M L2 gaz (ağın varsayılan fiyatıyla 0,87 ve 0,82 STRK). Birleştirilmiş kanıtın zincir maliyeti fatura sayısıyla artmaz. Starknet belgelerindeki işlem başına sınır 1,11 milyar L2 gazdır; iki işlem de bunun altındadır. İkisinin de ikinci sunumu "invoice already presented" ile reddedildi. Açık ağda ölçüm yapılmadı.

## 5. Veri akışı

1. Fatura programı her fatura için idareye bir istek gönderir, imzalı bir yanıt alır. Mükellef bu iki dosyayı saklar.
2. `tools/efi/batch_inputs.py` dosyaları okur, imzaları ön-denetler, devre girdisini yazar. Hiçbir kimlik ya da tutar ekrana basılmaz.
3. Noir devresi çalıştırılır; Barretenberg kanıtı üretir.
4. Doğrulayıcı mükellefe bir bağlam değeri verir; mükellef kanıtı o bağlam için üretir ve doğrulayıcıya kanıtı ile açık çıktıları verir.
5. Doğrulayıcı kanıtı ya kendi makinesinde ya da Starknet sözleşmesinde doğrular; kanıttaki bağlamın kendi verdiği bağlam olduğuna bakar (`pf.py verify --context`); idare anahtar özetini kayıtlı anahtarla karşılaştırır; nullifier'ları kendi defterinde (`--ledger`) ya da zincirdeki defterde arar.
6. Doğrulayıcı örnek açtırır (4.4).
7. İstisna hâlinde (uyuşmazlık, denetim) mükellef ilgili belgeleri açar.

## 6. Karar kaydı

| Karar | Sonuç | Gerekçe |
|---|---|---|
| TUNE-1 RSA yolu | Noir (`noir_rsa` + `noir-bignum`), anahtar özetiyle | Ölçüldü, çalışıyor. Cairo'daki RSA modülü de Noir kütüphanesi de bağımsız denetimden geçmemiş; denetim açık iş. |
| TUNE-6 Kanonikleştirme | Devre dışında yapılır, devre güvenmez | Şablon yöntemi (4.1) ve tek anlamlı okuma (4.2) |
| TUNE-7 Nullifier | Fatura başına, doğrulayıcının verdiği bağlamla, idarenin yanıt kodundan (FIC) | Faktoringde çifte temliki yakalar, doğrulayıcılar arası ilişkilendirmeyi engeller; mükellefin yazdığı alanlardan türetilmez, çünkü onlar yeniden imzalanarak değiştirilebilir |
| TUNE-9 Gizlilik kipi | Barretenberg'in gizlilik sağlayan kipi kullanılıyor | Dış iletişimde yine "minimum ifşa" denir: neyin açığa çıktığı Bölüm 1'de sayılıdır ve kütüphaneler denetimsizdir |
| Demo boyutu | Tek devre, 10 fatura | Özyinelemesiz en ucuz yol |
| Zincir | Starknet, Garaga doğrulayıcı + Cairo durum sözleşmesi | Çalışan tek zincir-üstü yol |

## 7. Sınırlar ve açık işler

- **Üretim sertifikası bilinmiyor.** Eldeki gerçek örnek 2021 test ortamından. Güncel idare sertifikası ve bir üretim çifti gerekiyor; test ortamına kendi erişimimiz için başvuru yapıldı.
- **Okunamayan biçimler:** saat farkı +01:00 ya da +02:00 olmayan tarihler ("Z" dahil), başlığında SubseqDelivType olan istekler, 2048 bayttan uzun istekler (ayar), 1280 bayttan uzun `<Invoice` etiketi. Bunlarda kanıt üretilemez; yanlış kanıt çıkmaz.
- **Henüz okunmayan alanlar:** fatura tipi, düzeltme faturasının hangi faturayı düzelttiği.
- **Mükellefin kimliği devrede okunmaz, bilerek.** İstekteki satıcı vergi numarası mükellefin kendi yazdığı bir alandır. Kanıt mükellefi imza anahtarının özetiyle adlandırır; kimlik, sertifika kurumunun onayladığı fiskalizasyon sertifikasından gelir (`pf.py verify --taxpayer-cert`). Sertifikanın kendisinin denetimi (kök, geçerlilik, iptal) olağan X.509 araçlarıyla yapılır.
- **Ölçek:** birleştirilmiş kanıt 1'den 4096'ya kadar her fatura sayısında çalışır (4096, sıralı liste devresinin kapasitesidir; daha büyüğü için listenin de parçalanması gerekir). Süre fatura sayısıyla doğrusal artar: ilk yaprakla birlikte yaklaşık 64 sn, sonraki her 10 fatura için yaklaşık 40 sn (ölçümler koşudan koşuya onda bir oynar). Bu hızla 1.000 fatura bir saatin biraz üstünde, 4.096 fatura dört saatin üstünde sürer; bunlar hesaptır, 100 faturadan büyüğü koşulmadı (100 fatura 426 sn sürdü, hesapla uyumlu). Yapraklar sırayla üretildiği için bellek fatura sayısıyla artmaz; yapraklar birbirinden bağımsızdır, birden çok makineye dağıtılabilir. Not: iç kanıt denetimi tanık üretiminde değil kanıt üretiminde yapılır; birleştirme testleri bu yüzden hep kanıt üretip doğrular.
- **Portaldan kesilen faturalar:** idarenin kendi portalından kesilen faturalarda mükellefin elinde imzalı dosya oluşmaz; bu faturalar kapsam dışıdır.
- **Bağlam doğrulayıcının işidir.** Nullifier'lar bağlama bağlıdır; başka bağlam başka nullifier demektir. Kanıtın taşıdığı bağlamı sorgusuz kabul eden bir doğrulayıcı tekrar sunuma karşı korunmaz. Defter sözleşmesi bağlamı kaydeder ama bir doğrulayıcının hangi bağlamı verdiğini bilemez; her doğrulayıcı yalnız kendi bağlamındaki kayıtlara bakar. Bir bağlam tek tür kanıt alır (10'luk ya da birleştirilmiş), çünkü iki türün nullifier'ları birbiriyle karşılaştırılamaz.
- **Kapsam nullifier'ı örnek açtırma kadar güçlüdür.** Birim ve cihaz kodlarını mükellef yazar; kodları değiştirip yeniden imzalayan mükellef başka bir kapsam nullifier'ı elde eder, ama açılan ilk faturada idare kaydıyla çelişir. Zincirde örnek açtırma yapılmadığı için aynı yanıtlar orada başka bir kodla yeniden kaydedilebilir. Yıl artık idarenin yanıta koyduğu tarihe bağlıdır, mükellef değiştiremez. Bir kapsam (mükellef anahtarı, birim, cihaz, yıl) bir bağlamda tek bir birleştirilmiş kanıta izin verir; daha uzun ya da başka faturaları kapsayan ikinci kanıt da reddedilir. İki sertifikası olan mükellef iki ayrı anahtar özetiyle sunabilir; doğrulayıcı sertifikadaki vergi numarasına göre kendi kaydını tutmalıdır.
- **Gizlilik sınırları:** 10'luk kanıtta bir faturanın FIC'ini ve bağlamı bilen kişi o faturanın sunulduğunu anlar. Mükellefin sertifikasını elinde tutan (idare, sertifika kurumu, yazılım sağlayıcı, kimliğin açıldığı doğrulayıcı) o mükellefin bütün kayıtlarını ilişkilendirebilir, çünkü anahtar özeti tuzsuzdur. Zincirdeki kayıt yılı, eşiği ve fatura sayısını herkese gösterir.
- **Doğrulayıcının hafızası.** Bir kanıt, daha önce sunulmadığını tek başına gösteremez. Zincir dışında `pf.py verify --ledger` kabul edilen nullifier'ları bir dosyada tutar ve aynı bağlamda tekrarı reddeder; kullanılmazsa araç nullifier'ları yalnız ekrana yazar. Araç bu değerleri kanıtın açık değerlerinden okur, mükellefin yazdığı özet dosyasından değil.
- **Defter sözleşmesinin davranışları:** bir bağlamın türünü o bağlamdaki ilk kayıt belirler, bu yüzden doğrulayıcı bağlamı beklediği kayıt düşene kadar kendisi ve mükellef arasında tutar; hiçbir kayıt geri alınmaz, sonradan başarısız olan bir örnek açtırmayı doğrulayıcı kendi kaydına yazar.
- **Zincirde gönderen:** kanıt gönderen hesaba bağlı değildir; işlemi gören biri aynı kanıtı önce gönderebilir. Kayıttaki gönderen hesap bilgi içindir, mükellefi göstermez.
- **Test anahtarı üretim anahtarı değildir.** Kayıtlı tek gerçek idare anahtarı test ortamına aittir; o ortamda uydurma faturalara yanıt alınabilir. `pf.py verify` üretim anahtarı olmayan bir anahtarla doğrulanan kanıtta 0 dışı çıkış kodu verir.
- **Doğrulama sonucu çıkış koduyla belirlenir.** Araçlar bir kanıtın geçerli olup olmadığına doğrulayıcı programın çıkış koduna bakarak karar verir; ekrana yazdığı metne bakarak değil (ilk sürümde metne bakılıyordu ve içinde kanıt olmayan, özel adlandırılmış bir klasör geçerli sayılabiliyordu; düzeltildi, testi var).
- **Denenemeyen bir nokta:** iç içe kanıtlarda son eşleme (pairing) denetiminin doğrulayıcıda yapıldığı varsayımı, bozuk bir iç kanıtla uçtan uca denenmedi; Barretenberg'in kanıtlayıcısı böyle bir kanıtı üretmeyi kendisi reddediyor, bu yüzden deneme için değiştirilmiş bir kanıtlayıcı gerekir.
- **Denetim:** devreler ve kullanılan kütüphaneler bağımsız incelemeden geçmedi. Kasım 2026'da ekip içinde devreleri yazmamış bir gözle iki karşı inceleme yapıldı. Birincisi iki açık buldu (nullifier'ın mükellefin yazdığı bir alandan türetilmesi; birim ve cihazın hiçbir denetime bağlı olmaması). İkincisi devrelerde açık bulmadı; doğrulayıcı araçlarında hatalar buldu (kanıtsız klasörün geçerli sayılması, tutar karşılaştırmasında ondalık hatası, açma denetiminin kanıtı doğrulamaması), ağacın örnek açtırmanın erişemeyeceği kadar derin kurulabildiğini ve belgelerdeki bazı cümlelerin koddan güçlü olduğunu gösterdi. Hepsi düzeltildi ve testleri eklendi.

## 8. Test durumu

Depoda yalnız sentetik veri vardır; gerçek örneklerle denemeler depo dışında yapılır. Bütün testler tek komutla koşar: `sh tools/test.sh` (hızlı küme, derlenmiş devrelerle yaklaşık 10 dakika) ve `sh tools/test.sh full` (10 faturalık devreler, sözleşmeler, yerel ağ ve gösterim dahil).

| Hedef | Test | Sonuç |
|---|---|---|
| `pf_xmldsig` | Birim testleri (base64, UUID, tarih ve aralıkları, saat farkı, tutar, baştaki sıfır, kod, onaltılık tablo, SignedInfo özetinin düz özetle karşılaştırması) | 27/27 |
| `pf_efi` | İstek okuyucu (sahte öznitelik, tekrar, eksik, kapanmayan etiket, tek tırnak, sekme ve satır sonu, ad alanı bildirimi, kapanış etiketleri, kısa imzalanmış belge), kısmen dolu devrede sayılan ve sayılmayan yuvalar, birleştirme yardımcıları (sıralı liste, dilim birleştirme, kapsam), örnek açtırma devresi (kapsanan aralıklar, ilk ve son, yanlış tutar, yanlış taraf, soldaki toplamın küçültülmesi, boş yuva) ; yanıt tarihinin yıla ait olması; dilim derinliği | 39/39 |
| İdare yanıtı | Kabul/ret: sahte imza, yanlış anahtar, bozuk alan | 7/7 |
| Mükellef isteği | Kabul/ret + "tutar gibi görünen metin" fark testi; mükellefin gerçekten imzaladığı ama kabul edilmemesi gereken belgeler (çift tutar, eksik sıra, bozuk tutar, kısa imza, ad alanı, sekmeyle gizlenmiş ikinci tutar, baştaki sıfır, başka saat farkı) | 14/14 |
| Yeniden imzalama | Aynı fatura dört ayrı biçimde imzalanır: IICSignature, cihaz ya da tutar değişse de nullifier aynı kalır; cihaz ya da tutar değişince açma taahhüdü değişir; başka bir yanıt başka nullifier verir | 6/6 |
| 1 fatura | Kabul/ret: kopuk bağ, eşik altı, yanlış yıl, önceki yıla ait yanıt, sahte imzalar, tutar değişikliği | 9/9 |
| 10 fatura | Kabul/ret: boşluk, yanıtın iki kez kullanımı, karışık birim/cihaz ve yukarıdakiler | 13/13 |
| Örnek açtırma | Doğru açma eşleşir; tutarı, sırayı ya da FIC'i değiştirilmiş açma eşleşmez. İdare kaydıyla karşılaştırma: aynı kayıt uyuşur (tutar sayı olarak yazılsa da); başka tutar, ondalık noktası kaydırılmış aynı rakamlar, üç ondalıklı tutar, başka cihaz ve bulunamayan kayıt alan adıyla fark verir; satıcının sertifikadaki vergi numarasıyla karşılaştırılması; kanıt olmadan `--first` reddedilir | 16/16 |
| Özet fonksiyonu | Araçların Python Poseidon2'si devrelerle karşılaştırılır: referans vektör, 0 ile 10 arası eleman sayıları, açma taahhüdü | 13/13 |
| Birleştirme (1'lik yapraklar) | Kanıt üreterek: 1, 2 ve 3 yapraklı geçerli ağaçlar; yanıtın iki yaprakta kullanımı; bunu baştan sahte sıralı listeyle gizleme; yapraklar arası boşluk; başka cihaz; eşik altı; başka denetim değeriyle kanıtlanmış yaprak; sonradan değiştirilmiş özet; yanlış yaprak devresi özeti; yaprağın birleştirici diye sunulması; tek yuvalı yaprağın iki fatura taşıdığının söylenmesi; biri çok büyük dört fatura; örnek açtırmanın erişemeyeceği kadar derin kurulmuş ağaç (üst kanıtta reddedilir) | 15/15 |
| Birleştirme (10'luk yapraklar) | Kanıt üreterek: geçerli 20, 23 (10 + 10 + 3) ve 7 fatura; boş yuvanın fatura sayılması; sıfır ya da 11 fatura taşıdığı söylenen yaprak; yapraklar arasında dört faturanın atlanması; yanıtın iki yaprakta kullanımı ve sahte sıralı liste | 8/8 |
| Birleştirilmiş kanıtta örnek açtırma | Dört geçerli kanıtta (3, 4, 23 ve 7 fatura), her açma `spot_open` kanıtıyla: istenen fatura açılır; tutarı ya da cihaz kodu değiştirilmiş, başka sıra numarası için sunulmuş ya da başka faturanın kanıtıyla sunulmuş açma reddedilir; ilk ve son fatura ilk ve son olarak kabul edilir, ortadaki ya da ters uçtaki kabul edilmez; tohumun belirlediği noktayı kapsayan fatura kabul edilir, aynı açma başka çekiliş ya da başka tohum için, başka bir fatura da o çekiliş için reddedilir; mükellefin aracı ikinci tohuma ve on birinci çekilişe cevap vermez; biri çok büyük dört faturada on çekilişin en az yedisi büyük faturayı ister | 53/53 |
| Starknet defteri | Gerçek 10'luk ve 20'lik kanıtlarla: kayıt, ikinci sunum, kayıtsız ya da kaldırılmış idare anahtarı, yalnız sahip anahtar ekler, değiştirilmiş kanıt, birleştirilmiş kanıtın 10'luk girişten sunulması, tanınmayan yaprak, birleştirici ya da sıralı liste devresi; aynı bağlamda öteki tür kanıtın reddi (iki yönde) | 16/16 |
| Yerel ağda uçtan uca | Sözleşmeleri yükle ve kur; 10'luk ve 25 faturalık kanıt için: idare anahtarını kaydet, kanıtı sun, aynı kanıtı yeniden sun (reddedilir). Tek komut, yaklaşık 4 dakika | geçti |
| Komut satırı, dosyalardan (`tools/test_cli.py`) | Diske yazılmış imzalı istek ve yanıttan kanıt; `verify` çıktısı ve çıkış kodları: doğru ve başka bağlam, mükellefin ve başkasının sertifikası, değiştirilmiş açık değer; eşik üstü iddia ve başka yıl için kanıt üretilememesi; bağlamsız kanıt üretilememesi; defterle ikinci sunumun reddi; yanlış yazılmış bağlamda hüküm basılmaması; içinde kanıt olmayan, yanıltıcı adlı klasörün geçersiz sayılması | 14/14 |
| Gösterim (`tools/demo.py`) | 25 uydurma fatura, iki mükellef: dürüst olanın kanıtı kabul edilir, dört açmanın dördü idare kaydıyla uyuşur; bir faturayı 500.000 fazla gösteren mükellefin kanıtı da kabul edilir, ama tutarla yapılan çekilişler şişirilen faturayı ister ve karşılaştırma tutar farkını gösterir | geçti |
| Uçtan uca araç | Gerçek 2021 çiftinde `prove` -> `verify`: geçerli, idare anahtarı kayıtlı ama üretim anahtarı değil uyarısı, sertifika eşleşiyor, başka bağlamla ret; sentetik 10'lukta geçerli ama "anahtar kayıtsız" uyarısı; değiştirilmiş açık değerde geçersiz; 3, 13, 25 ve 100 sentetik faturayla `prove --keep` -> `verify` -> son faturanın örnek açtırması | elle koşuldu |

## 9. Sıradaki adımlar

1. Doğrulayıcıları ve defter sözleşmesini Starknet Sepolia'ya yüklemek ve gerçek ücreti ölçmek.
2. Test ortamından kendi kestiğimiz 10 ardışık gerçek faturayla demo.
3. Örnek açtırmada idarenin kamu servisine sorgunun araca bağlanması (karşılaştırmanın kendisi yapıldı; sorgu için idarenin servis biçimi gerçek veriyle görülmeli).
4. İade faturaları sorunu (4.4): brüt toplamın gerçek fatura ve iade çiftleriyle büyütülmesi ve yeniden imzalanarak küçültülmüş iade faturası. Bakılacak yollar: brüt toplam için açık bir üst sınır; idare kaydının bir faturanın sonradan düzeltildiğini gösterip göstermediği (gerçek veriyle görülmeli); 10'luk kanıtlarda tutarla sorma.
5. Eksik alanlar ve biçimler (Bölüm 7).
6. 4096'dan büyük kümeler (sıralı listenin de parçalanması) ve yaprakların birden çok makinede üretilmesi.
7. İç içe kanıtlarda son eşleme denetiminin bozuk bir iç kanıtla uçtan uca denenmesi (Bölüm 7).
8. Bağımsız inceleme.
