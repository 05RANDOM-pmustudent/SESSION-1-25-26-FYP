# API contract

All paths are same-origin. JSON responses use UTF-8 and `Cache-Control: no-store`. Obtain the opaque session cookie and `csrf_token` from `GET /api/bootstrap`. Include that cookie and `X-CSRF-Token` on every mutation. Browser Origin, when supplied, must match the server origin. Login and logout rotate the session and return a replacement token.

| Method | Path | Result / access |
| --- | --- | --- |
| GET | `/health` | Startup/version probe; no session or database lookup |
| GET | `/api/bootstrap` | Models, capabilities, limits, history, community, CSRF and admin state |
| POST | `/api/analyze` | One NDJSON response with stages then saved result or terminal error |
| GET | `/api/history` | Current session owner's recent results |
| GET | `/api/analyses/{share_id}` | Bearer-link shared result; extracted screenshot text omitted |
| POST | `/api/feedback` | Vote on a saved result owned by this session |
| POST | `/api/login` | Configured administrator login; new cookie and CSRF token |
| POST | `/api/logout` | Revoke current session, issue anonymous cookie and token |
| GET | `/api/admin/overview` | Protected counts, latest analyses/feedback, models and pipeline counters |
| DELETE | `/api/admin/analyses/{id}` | Protected deletion with feedback cascade |
| DELETE | `/api/admin/feedback/{id}` | Protected feedback deletion |
| GET | `/api/news` | Manual headlines retrieval; one-hour cache |

## Analysis input

URLs and news use `Content-Type: application/json`:

```json
{"kind":"url","input":"https://example.com/","inspect":false}
```

```json
{"kind":"news","input":"An English statement to review."}
```

`inspect` must be a boolean and is only supported for URLs. News text must contain 20–12,000 characters after trimming; URLs are capped at 2,048 characters. URLs accept HTTP/S on ports 80/443; local/private address literals, local hostname forms, embedded credentials and malformed inputs are rejected. Default URL classification does not fetch or resolve the website. `inspect:true` adds a constrained public-page fetch and checks every resolved address before connecting.

Screenshots use `multipart/form-data` with a `kind=screenshot` field and binary `file` field. Allow the browser to supply its multipart boundary. Image bytes are capped at 2,000,000 and the complete request at 2,500,000. English Tesseract must be available. Supported validated single-frame formats are PNG/JPEG/WebP/BMP; image dimensions are bounded before decoding.

The response content type is `application/x-ndjson`. Each line is a complete JSON event; transport chunks can contain partial lines or several lines, so buffer until a newline. Example:

```json
{"event":"stage","stage":"queued","message":"Your analysis is in the local queue."}
{"event":"stage","stage":"classifying","message":"Assessing URL patterns with the local phishing classifier."}
{"event":"stage","stage":"saving","message":"Saving your result in local history."}
{"event":"result","result":{"kind":"url","label":"review","score":50,"model":"...","model_version":"...","id":"...","share_id":"..."}}
```

The result above abbreviates fields for illustration. Real results also contain `probability`, `signals`, `limitations`, held-out `metrics`, `input_label`, `created_at`, `cached` and `elapsed_ms`; screenshots add `extracted_text`, and optional website inspection adds `checks`. Combined analyses can add `components` with score, label and model provenance. `score` is an integer 0–100 derived from model probability; it is a dataset estimate, not a verified risk percentage. Labels are `low_risk`, `review` or `high_risk`; news always uses `review`.

For combined screenshot or inspected-website results, the top-level score is the largest component score; `probability` and `metrics` follow the component supplying that score. This maximum is not a calibrated estimate that fuses the models. The top-level label preserves the most severe component or review-policy label independently of the numeric score. An explicit credential request can promote a low-risk label to `review` without changing its model probability. Read `components`, `signals` and `limitations` together; the top-level label need not equal the label associated with the score-supplying component. URL-only model labels use 0.05/0.95 thresholds, SMS labels use 0.2/0.8, and news always requires review.

Stage ordering depends on kind, optional inspection and reuse. Clients should tolerate additional stage events. A stream is successful only after an `event:result` line. After response headers have been sent, failure is a terminal line:

```json
{"event":"error","error":{"code":"analysis_failed","message":"Analysis could not be completed and saved. Please try again."}}
```

HTTP 200 alone does not imply analysis success. Ending a response without a terminal result/error means the client disconnected or the stream failed. Cancelling the browser request stops delivery; already running shared computation may finish for reuse. Retrying the same input from the same owner reuses computation where available and updates the existing saved row.

## Feedback and authentication

Feedback body:

```json
{"analysis_id":"saved-result-id","accurate":false,"reason":"missed_signal","other_text":"Optional explanation."}
```

`accurate` must be a boolean. `reason` is at most 120 characters and `other_text` at most 2,000. Unowned or missing analyses are rejected with HTTP 400. Feedback does not train a model automatically.

Login body is `{"username":"admin","password":"your-configured-password"}`. Administrator access is disabled until configured; there is no built-in password. Logout does not require a JSON body but still requires CSRF. All administrator reads and deletes require an authenticated admin session; deletes additionally require CSRF.

## Errors and bounds

Before a stream starts, failures use ordinary JSON `{"error":{"code":"...","message":"..."}}`. Relevant statuses are 400 invalid input or unowned feedback target, 401 authentication, 403 CSRF/origin, 404 missing result/route, 413 upload bound, 415 content type, 429 rate limit and 503 busy/unavailable. Rate-limited responses include `Retry-After: 60`. Analysis capacity and HTTP admission are separately bounded; do not repeatedly retry a busy response without a delay.

No CORS integration, external inference callback, WebSocket, job-status polling or distributed queue is required for this contract. Reverse proxies must preserve cookies, pass streaming response chunks promptly and provide forwarded client/scheme information only through explicitly trusted proxy addresses.
