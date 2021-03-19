# LNP/BP Invoice Library

Library providing functionality for doing universal invoices covering Bitcoin,
Lightning Network and RGB (on-chain and LN) according to LNPBP-38 standard.
Supports address-, UTXO-, channel-, miniscript-descriptor- and PSBT-based
invoices with such features as:
- Paying arbitrary amounts (donations etc)
- Recurrent payments
- Per-item prices with multiple item orders
- Expiration dates
- Currency exchange rate requirements
- Extended information about merchants, invoice details etc
- Optional merchant signatures

Read more on this invoices in 
[slides](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/Universal%20LNP-BP%20invoices.pdf) 
or watch [YouTube recording](https://www.youtube.com/watch?v=R1QudCywRGk) of one
of LNP/BP Association development calls discussing universal invoices.
