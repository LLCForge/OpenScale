;; Örnek OpenScale eklentisi (ABI 1, docs/eklenti-abi.md).
;; .example üst alanının altındaki her adı engeller; geri kalanında görüş
;; bildirmez. testdata/plugins/ornek-engel.wasm bu kaynağın baytlarıdır;
;; baytları internal/plugin/wasm_test.go içindeki kodlayıcı üretir
;; (go test ./internal/plugin -run TestExampleFiles -update). Bir WAT
;; derleyicisiyle derlenirse bölüm sırası aynı kaldığı sürece aynı
;; davranışı verir.
;;
;; İstek düzeni (tampon 1024'te): [0]=1, [1:3]=sorgu türü, [3:5]=ad
;; uzunluğu (küçük uçlu), [5:]=ad (küçük harf, sondaki nokta yok).
;; Yanıt: [0]=karar (0 görüş yok, 1 izin, 2 engel, 3 yeniden yaz).
(module
  (memory (export "memory") 1)

  (func (export "osp_abi_version") (result i32)
    (i32.const 1))

  (func (export "osp_buffer") (result i32)
    (i32.const 1024))

  (func (export "osp_dns_query") (param $len i32) (result i32)
    (local $nl i32)
    (local.set $nl (i32.load16_u offset=1027 (i32.const 0)))
    (if (i32.ge_u (local.get $nl) (i32.const 9))
      (then
        ;; Adın son 8 baytı ".example" mi? (küçük uçlu i64)
        (if (i64.eq (i64.load (i32.add (local.get $nl) (i32.const 1021)))
                    (i64.const 0x656c706d6178652e))
          (then
            (i32.store8 offset=1024 (i32.const 0) (i32.const 2))
            (return (i32.const 1))))))
    (i32.store8 offset=1024 (i32.const 0) (i32.const 0))
    (i32.const 1)))
