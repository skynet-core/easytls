# easytls

CLI utility to help you to generate TLS keys to play with mTLS auth

## Usage

    easytls generate root-ca -n rootCA # will generate root-ca key and certificate
    easytls generate server -o ./pki -n server1 --ca-crt ./pki/rootCA.crt --ca-cert ./pki/rootCA.crt # will generate server key and certificate
    easytls generate client -o ./pki -n client1 --ca-crt ./pki/rootCA.crt --ca-cert ./pki/rootCA.crt # will generate client key and certificate
