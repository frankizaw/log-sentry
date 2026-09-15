# Log Sentry

Mały skrypt w Pythonie, który skanuje logi dostępu serwera WWW i oznacza requesty wyglądające jak typowe ataki.

*Read in English: [README.md](README.md)*

## Co robi

- Czyta plik logu Nginx/Apache linijka po linijce.
- Sprawdza ścieżkę każdego requestu pod kątem wzorców:
  - Directory traversal (`../`, `/etc/passwd`)
  - SQL injection (proste payloady typu `UNION SELECT`, `OR 1=1`)
  - Skanowanie w poszukiwaniu wrażliwych plików (`.env`, `.git`, strony logowania do panelu admina)
  - Podstawowy XSS (tagi `<script>`)
- Liczy, ile razy dany adres IP dostał odpowiedź `404 Not Found`, żeby wyłapać adresy skanujące strony, których nie ma.
- Na koniec drukuje krótki raport.

Brak zewnętrznych bibliotek — tylko standardowa biblioteka Pythona (`sys`, `re`, `collections`).

## Użycie

```bash
python3 analyzer.py <ścieżka_do_pliku_logu>
```

Przykład:

```bash
python3 analyzer.py sample_access.log
```

## Status

To projekt nauki, a nie gotowe narzędzie produkcyjne. Wykrywanie opiera się na prostym dopasowywaniu wzorców i da się je łatwo oszukać — to raczej punkt startowy do zrozumienia, jak działa podstawowy IDS, a nie zamiennik prawdziwego WAF-a/IDS-a.
