#!/bin/bash

curl -v -X POST \
 --cacert ../ssl/server/server.crt \
 --cert ../ssl/client/client1.p12:123456 \
 --cert-type p12 \
 -H 'content-type: application/json' \
 -d '{ "adminCertificate": "MIIDPTCCAiUCFBd+dfQuley5j4MetX3iewvIxHZDMA0GCSqGSIb3DQEBCwUAMF0xCzAJBgNVBAYTAkNaMRAwDgYDVQQIDAdDemVjaGlhMQswCQYDVQQHDAJDQjENMAsGA1UECgwEM0tFWTEMMAoGA1UECwwDREVWMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjAwOTI1MTE1NDU3WhcNMzAwODA0MTE1NDU3WjBZMQswCQYDVQQGEwJDWjEQMA4GA1UECAwHQ3plY2hpYTELMAkGA1UEBwwCQ0IxCzAJBgNVBAoMAkNGMQwwCgYDVQQLDANERVYxEDAOBgNVBAMMB0NMSUVOVDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/SsO+9IzQ85xxyiT+ou8RDNxZMP0Ja8YKrdu19BTFjyLtVLpb+I1XqzlXFdJcObYZ5ZboyALB00i5Ds0TTs8ydgEeaw0K2O96DnGh4z5r4qLuF+fpVR+3A8kKRSrqJN1JNPFeb+NKsilUNvx5plZBm5+VTd64Sop6r1DALEDBS8AxRJSgp4x/oCq+T4zLh9XDyVUQ68axLgF86sS4YcBYKQVTH7KwRx+FGPFnBqt2ll2IherJ1N1dheXdLqzPYY+uIhs55wUPRhQibjiJhM9NgMYsmOPZRzsPIr6+gUil82rmSfyMg/A0wT4dsm6MT7ly6PPRyxoRvhNvfn96FsCRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAI+YNR82n23p9014wa+99aEWJfujlirY07jhAQmsGTkkFM5QTNJzwi6VYnUwjlJMOXw8fEiBVRHUiyLV5RWZGiGZuLdCZgYCjtzCtWuOPidShAK5GpLDipG9upZ+RCNpBXVbb6J5tEI0esTSxZ/jwj2JqZZayhRmRXL/j8vGRn74atTILeFwUIYsSreoMI8wG1Rk0que09LgP1RmCiSl1GUSTL/lrK/dYaw0orZwUxzKg/KNnTYprYiAIVRsHUz8bkd6mGEBCfDdpEp0l7laBej2R8RhGDwuxjma1ZrwlCsKLlpdn2lwzqIEc+Zl7dxiLTb1NLMH80f4LCuF1iFCD6E=", "name": "admin" }' \
 https://localhost:8443/api/v1/local/admins