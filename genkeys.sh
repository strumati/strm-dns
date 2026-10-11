openssl req -x509 -newkey ed25519 \
	-keyout server-key.pem \
	-out server-cert.pem \
	-days 365 \
	-nodes \
	-subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

openssl rand --base64 32 > key
