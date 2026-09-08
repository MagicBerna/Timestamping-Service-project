# Diagrammi di Sequenza del Progetto TSS

I diagrammi sono stati generati sia in formato **PNG ad alta risoluzione (300 DPI)** che in formato vettoriale **SVG**, con lo stile e l'estetica richiesti (box grigi di esecuzione, frecce numerate e banner di stato).

---

## 📁 File Generati

| File Immagine | Descrizione del Protocollo |
| :--- | :--- |
| [`fig1_handshake_protocol.png`](fig1_handshake_protocol.png) / [`.svg`](fig1_handshake_protocol.svg) | **Handshake TLS 1.3 & Certificate Pinning**: negoziazione ECDH effimera, scambio certificato $pubK_c$ (`server_conn.crt`), verifica estensioni SAN e derivazione chiavi con Perfect Forward Secrecy. |
| [`fig2_login_flow.png`](fig2_login_flow.png) / [`.svg`](fig2_login_flow.svg) | **Autenticazione e Scambio Nonce (`LOGIN`)**: trasmissione credenziali con nonce client $N_c$, verifica hash+salt in `users.json`, generazione nonce server $N_s$ e inizializzazione contatore anti-replay `expected_seq = 1`. |
| [`fig3_timestamp_request.png`](fig3_timestamp_request.png) / [`.svg`](fig3_timestamp_request.svg) | **Richiesta Timestamp e Rilascio Token (`TIMESTAMP` - Happy Path)**: calcolo locale SHA-256 (Data Minimization), verifica `seq`, aggiornamento quota ($n_r \gets n_r - 1$), firma payload canonico 40B con chiave separata $privK_{ts}$ (ECDSA P-384). |
| [`fig4_edge_cases.png`](fig4_edge_cases.png) / [`.svg`](fig4_edge_cases.svg) | **Gestione Casi Limite ed Errori**: (1) Rifiuto per quota esaurita ($n_r = 0$, profilo Charlie); (2) Rilevamento di Replay Attack con disallineamento `seq` e chiusura immediata del socket TLS. |
| [`fig_weak_hash_rejection.png`](fig_weak_hash_rejection.png) / [`.svg`](fig_weak_hash_rejection.svg) | **Rifiuto per Hash Debole (MD5)**: tentativo di richiedere un timestamp con hash a 128 bit (32 caratteri hex); rilevamento sintattico del server, rifiuto immediato senza scalare crediti e prevenzione da attacchi di collisione. |
| [`fig_quota_exhausted.png`](fig_quota_exhausted.png) / [`.svg`](fig_quota_exhausted.svg) | **Rifiuto per Quota Esaurita ($n_r = 0$)**: richiesta con crediti residui azzerati (Charlie); verifica in memoria RAM su `g_users`, blocco dell'emissione della firma e notifica di errore al client. |
| [`fig5_offline_verification.png`](fig5_offline_verification.png) / [`.svg`](fig5_offline_verification.svg) | **Verifica Crittografica Offline (`tss_verify`)**: validazione autonoma del bundle $\langle h, t, \sigma \rangle$ da parte di un auditor/terzo tramite la chiave pubblica $pubK_{ts}$ senza connessione di rete. |

---

## 📝 Come includere le figure in LaTeX (`Report.tex`)

Puoi includere direttamente le immagini PNG nel tuo file `Report.tex` usando il pacchetto standard `graphicx`:

```latex
% Esempio: Handshake TLS 1.3
\begin{figure}[htbp]
    \centering
    \includegraphics[width=0.72\textwidth]{figures/fig1_handshake_protocol.png}
    \caption{TLS 1.3 Handshake and Certificate Pinning protocol.}
    \label{fig:handshake}
\end{figure}

% Esempio: Protocollo di Login
\begin{figure}[htbp]
    \centering
    \includegraphics[width=0.72\textwidth]{figures/fig2_login_flow.png}
    \caption{Authentication and Nonce Exchange protocol (\texttt{LOGIN}).}
    \label{fig:login}
\end{figure}

% Esempio: Timestamping Token Generation
\begin{figure}[htbp]
    \centering
    \includegraphics[width=0.72\textwidth]{figures/fig3_timestamp_request.png}
    \caption{Timestamp request and cryptographic token issuance (\texttt{TIMESTAMP}).}
    \label{fig:timestamp}
\end{figure}

% Esempio: Casi Limite
\begin{figure}[htbp]
    \centering
    \includegraphics[width=0.72\textwidth]{figures/fig4_edge_cases.png}
    \caption{Edge cases: Quota exhaustion and in-session replay attack handling.}
    \label{fig:edge_cases}
\end{figure}

% Esempio: Verifica Offline
\begin{figure}[htbp]
    \centering
    \includegraphics[width=0.72\textwidth]{figures/fig5_offline_verification.png}
    \caption{Offline token verification workflow via \texttt{tss\_verify}.}
    \label{fig:verify}
\end{figure}
```

---

## 🛠️ Come rigenerare o modificare i diagrammi

I diagrammi sono generati dallo script Python:
```bash
python3 scripts/generate_diagrams.py
```
Puoi modificare i testi, le dimensioni o i passaggi direttamente all'interno di `scripts/generate_diagrams.py` e ri-eseguire lo script in qualsiasi momento.
