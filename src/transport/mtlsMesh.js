/**
 * AegisMCP - Distributed Remote MCP Tunneling & Mutual TLS (mTLS) Mesh
 * Zero runtime dependencies (uses native node:tls, node:https, node:crypto).
 */

'use strict';

const tls = require('node:tls');
const https = require('node:https');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

const ERROR_CODES = {
  AEGIS_MTLS_UNAUTHORIZED: -32008
};

// Pre-computed standard 2048-bit RSA X.509 test certificates & keys
// CA -> issues server.crt (localhost) and client.crt (Aegis-Authorized-Agent)
// Untrusted -> self-signed Malicious-Agent (not trusted by CA)
const TEST_CERTS = {
  "caCert": "-----BEGIN CERTIFICATE-----\nMIICrDCCAZQCCQCwgFCxtaMg2TANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1B\nZWdpcy1Sb290LUNBMB4XDTI2MTEwNDE0MDEyMVoXDTM2MTEwMTE0MDEyMVowGDEW\nMBQGA1UEAwwNQWVnaXMtUm9vdC1DQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAL9iiraty3JeDSFPfhGYmqLdQT3/4rOWtnKdhCUvWbPKcCql3Sl0mYAs\nEstR0p8lnCT12g1lFoNA2epGEJLRYJ6s/8/O1D4FdzJP4tKPm/+Ory4x1UxZ1drd\nqaWw0N5rVHCrQ8o/r/myCVYzCU/JfIIJuyFFzN0ecS4hm/FJRWSAZ1Z0qbVzEzHg\niNgKWpLqHFamUMue1YN43FzHZVHUb89UC5JAwaC2XRgRSevYQkfsTkNXE8fh4Hwp\n/GTGiXk/mftimu/2BQjzFiZXjeazpas5vcPr4xj+578OQBmAjylAnarOuCFzwPVJ\nBTaRGO0r8hMJINZ4pTd6j0xvk7z9aDMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA\nU9nH41QLPKsJpQnGHY1TbFNYqFfCZZRUomQyawV+A9Btt+icZOya/u3B8DZjaw7O\nGTdpTpMEhSfo2UviJ1V2fDNlnHF0EF167dOEZoebiU27X15nb7jcaJyou2cwKb9+\nzW9xIgOFjhJoHnwVZ7eLZV9zMd0d0lgqwjaRvtR+FwKvgHt43FtjubhLbmNvs/oA\n9chhNZy+JIojO6KjjhmBkZH06Wz4NhP/bNTmeUWlv2/+4EFVgBimRm7DL//mlsaJ\n2/jeYCgE+PCtwQN6Nq3JS9TlDGKjUyVNdPw97aW6Bq9fLud8yaODL568YCaSN4fp\nCfrVgjuvOvrOH72Hugtf5w==\n-----END CERTIFICATE-----\n",
  "serverCert": "-----BEGIN CERTIFICATE-----\nMIICqDCCAZACCQDovgOTPguYyTANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1B\nZWdpcy1Sb290LUNBMB4XDTI2MTEwNDE0MDEyMVoXDTM2MTEwMTE0MDEyMVowFDES\nMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAr4hN0FX/vIUTjkBWOGVQ+SutqBS2vxH6n7Z7CHDYq8ML7sAKW3QD3OQHQrtb\nAB0eahxYaoyiLgg2p/nqgB7X1ppjrx1CiqUQtziUCFVPOp9ev76283+6jVjGE6jO\nyaQ+ExlQpfYuZsYhr99lSLNkeW8EOLDLV5JGJ9/Taxfl5jVwQrqm05cMsy59Rqh/\nA6okKn9kP/5j9hNDMI5u1OEN8Ys1NDYdmet00tKo2nMs8OOOJk1QIPuCRnoMOvC3\n/zB2gaU3NuPdDUNSd2uGWuDJ11+eA/G5//qQWRHDuKSk1t3QEAeSVoTnuLqSTHH+\nlbUTZ0lLiFruxlElKZt4rTA8cwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAFYMy8\nWCcZQ3nmVC0pi0UmJxrHoNYSsuvhXpF/XGNan6A0v8cHh4/w61T2Tl5AdGOOK/O8\n0x4+bQB6EHDOTVvrYMuPuUihcqR57Akp+FNq4P+ITQxma4H7RRNs0OAnVPepufGg\nnwi0uw28FLANLTK1S+6e463XpmfXXklXoc0s9N4alBeBA6Ao+tGKF2rsUXrmnuar\nORCLU/9YSQcVNZYHbWP9cfNb39wcNXVeLMICqdF23nT6IzjzuBFdvuzEJQq1iGUv\n/eCuMv7KLAhJrV1jvt2fahfWLNPIQQcDlBjZ0gjs3xY3kkMaDAhtqWtoUxzg3tlY\nDdPsh2PumY/pCwza\n-----END CERTIFICATE-----\n",
  "serverKey": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCviE3QVf+8hROO\nQFY4ZVD5K62oFLa/EfqftnsIcNirwwvuwApbdAPc5AdCu1sAHR5qHFhqjKIuCDan\n+eqAHtfWmmOvHUKKpRC3OJQIVU86n16/vrbzf7qNWMYTqM7JpD4TGVCl9i5mxiGv\n32VIs2R5bwQ4sMtXkkYn39NrF+XmNXBCuqbTlwyzLn1GqH8DqiQqf2Q//mP2E0Mw\njm7U4Q3xizU0Nh2Z63TS0qjacyzw444mTVAg+4JGegw68Lf/MHaBpTc2490NQ1J3\na4Za4MnXX54D8bn/+pBZEcO4pKTW3dAQB5JWhOe4upJMcf6VtRNnSUuIWu7GUSUp\nm3itMDxzAgMBAAECggEBAJF0/iZ6XWW3UTE8Fza8npEcpNb380f6ehkHeoTQHnyX\nMLgz42FNjjXpsCqYXxyFBMMhohMJXwuOOtyPuMdax7lKTvi54n5JssRh2indp74I\neteiDrFRUyH2Qo3gARwPQnFJNQ+SJXl9DkVTdfb80XHfkTv5JUf4KrK4Q9YnA5fz\nqFGvrs4yGf9br440tPEV12sWb115nqj0KDqfQaQJwdu8qhXjECIXDpDk7SBqyqlA\ncscQwXqXycfoGx0COOFAOejsVdT4k/h4+NFbUViMm/m232skCH6rJLSvgBOIu6Il\nbcOAftHGavmVgY3b7dVPPigMS0ZSHQiA/nmUgWsBbEECgYEA44szSJ1IZwD51hzg\n9zOK8QdJGC9u+6St7g4BLC0SjRM/4rtblrxTUhwOTk5A0Y3hf6FBpSab9jZziM8/\nqm/bO3eXHV+eeVloEpFBF70l4UCH30KZBeboxqCbFHrENeW/G3ZwVCkvibv88AZj\n/Au6IjV5RiUsiWn1hfxJkMBIqvsCgYEAxXv26hKg5MeKxVKs8spITVxt9zJmqQlW\nBDHFQn03EQx1kYzfZp4OKtwVksSmdEHAU5u2ROXaQaRG1XSQ87/S5+tPZzLSVErw\nwe8VbusfVHziX88JwfGk/sL75Pv0T5cxhgqjITRXg1vTjEW6KUzFPpSfTUVTmckM\nwR+d6rfjeukCgYEAz7OKlmfrZQqBAy7NMxi7ZRQPZqI1nkJN+ZSTAW4LFvdRQ3de\nPROewr6VWGkZxa7K/aOGtmetyWsevuze4obECV46dDeKAp7X3sr0LeUcJKaw39x8\nreR+6oBDzsfZPpF+hmTwWAJYQFN2qOpMbg+OUheZoavhIXW1Bh6qUBUUv+0CgYAO\nZ1g/AlTR2uv4MGuE2dQkMFWk7fwm4BNyAt9MVi2qBKqejxPMPEL0RVEdf1JUsGcC\nshy9MbaVixHPh8z6ukb7u2HzOPW2SDD/NBzwFh4W33TzX/pqNuG94yLUNLxBAdoO\n2L/FMDgh0JTBamSFlp/cTKLB1Aig8tUHUPMHp5nj4QKBgBIkQeBtQt6HxWjdXNDu\n/qXjWYjEVUi+ig1Is9YO42IKk8QxrEVrEGaoFhJX91cjPi2Lu6yCwsuWssz3rJdA\nkdNjghf02a6Ww3rpdk/asDeGyRn0BUTa7MuYFrJyaXzWo+E630pMey+peqyTQ6ad\nXRYEp/9KedTCuwYjrKCI5KWe\n-----END PRIVATE KEY-----\n",
  "clientCert": "-----BEGIN CERTIFICATE-----\nMIICtTCCAZ0CCQDovgOTPguYyjANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1B\nZWdpcy1Sb290LUNBMB4XDTI2MTEwNDE0MDEyMVoXDTM2MTEwMTE0MDEyMVowITEf\nMB0GA1UEAwwWQWVnaXMtQXV0aG9yaXplZC1BZ2VudDCCASIwDQYJKoZIhvcNAQEB\nBQADggEPADCCAQoCggEBANtmfrlmZ4RcdyiO6F7b+GARY9NP6aPZkZ4NgpPmUshM\npEOv4VveQQ5/gyyxP1b5aFBYEb3LWSYfp3MJdng8PVaGRwXRuUz/nvzfqERi3eOV\n1wefBzoTBlV1TNnLnurEAJWrsBoEJn91DQ86EFoywCPq6SMWB5LBRFHmb9ieAlgu\nmsQx5LWV2wFP130210/AAI2wa2MUXJ+xYMg3lxz2SYvpMoVZR7MyGWSB0LMCCZAF\nCN3gooRlvoaIdKxj4E8qe+IRNc+KeRwDNIeeHjmGoj+NmRE+V42hKu4sMStjmIuQ\nlRmbch7EGIjY9AoX2Rbm/eCgz+pR8JzVJTGsfcF1gmkCAwEAATANBgkqhkiG9w0B\nAQsFAAOCAQEAqm1dADKrm+nkoVxsNgceW364kFxTzhXuClqk+o4cNGdefj58/SC9\nx5NN6O/elfLqvdCJ03KARU8o798REfcWtimkUCFAiVoZDmNiX9LADq5noufFh+UV\nfbyz9u2+RSRcDcaBxakxtQPW/uBKUBXDgbZrIrNngPvd9S/yCGXj6Y8bqKIMO7J3\nPOtEfcPL2r8ZgucR3fc4hLfkHAklmaDuwfwe8xUM5c6yzoX4xMKYHURUst5drAJB\ns9DHUP4h5FxjJ/SVesf0FOHP3tIpQbhnuW5MwpiWlzsqnjZTCvJ6Y09mJd6ENFoF\nfH/PhWf9yQzLxZ82wLm7jcSkSym+ISPP1w==\n-----END CERTIFICATE-----\n",
  "clientKey": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDbZn65ZmeEXHco\njuhe2/hgEWPTT+mj2ZGeDYKT5lLITKRDr+Fb3kEOf4MssT9W+WhQWBG9y1kmH6dz\nCXZ4PD1WhkcF0blM/57836hEYt3jldcHnwc6EwZVdUzZy57qxACVq7AaBCZ/dQ0P\nOhBaMsAj6ukjFgeSwURR5m/YngJYLprEMeS1ldsBT9d9NtdPwACNsGtjFFyfsWDI\nN5cc9kmL6TKFWUezMhlkgdCzAgmQBQjd4KKEZb6GiHSsY+BPKnviETXPinkcAzSH\nnh45hqI/jZkRPleNoSruLDErY5iLkJUZm3IexBiI2PQKF9kW5v3goM/qUfCc1SUx\nrH3BdYJpAgMBAAECggEAapru0F81xVa4f3iQ6CayFNveSXr256p72vRtkjfD2ZeD\n6W+4bM8dhVHoBvtI75XYXdGtLS91bdTLpFXgvqNmmng8YlN5WjSKqAx00mXHsyHH\njehztoAv/64zXVBXM3NxZUg7FSkXG69gXRm1gF5QhiNKjMXTgDdwXus9RV/he76i\n/BpVdVMxpvN/Nck++O6j36hBd1liGOPaMPpjXiJVBxbWPDH64BL2KVtdiKzL9I5k\nXxqWIpytRYR5vJESKzc3kZWYDisf38OxkX+R4fjxWvBVG0Wu4Gln4513XFH9Iufv\nTJ3ZnzA5jt5UfBgdv3biFxSWDd9QR0ILftDW2zybkQKBgQD1C829CQnuhKGi9JB2\nnmYbhl86vtijV9orhSAI6OZ9sMKloWJrwOx9uMyU5h5S1IgemGRwvWp/XnsZ5KT1\nEQ8fEJ+2RJYgiyNZr5tp9Y48NzKdljGqRjgW3EKgGQLLoV/KgOnAX7r52XVOzx3G\ngmcYYP1Q6TnDdmOYQoQcM5d9WwKBgQDlNTaTh9F8sWBN3O3bKQ7NV718JhdwdZ3A\nVVo2s1tOoE4HOPwsKTaKbqFF7e2Md67AKovQCxEdPt6SkFlpAWI+8CTKiMY/t7ko\n2LV39Yyliw8fyfCWNKkqFtJLHdCpgMWo09I4DoMmFqVAHCp0JaZwoAf6FKJ/WrY3\nGdO7JG32iwKBgAqGgkTPYZTUL5kvRhFCRoKCKA7+6ZFCkcVyx2h6kIPvlrzEjNSy\nCbZwvKDcrYrDREGELDRHfo6QAVugXZGFNRARh7qtgYFOWKtehp9rg7uEZ3ErZWC5\n+WjJ9zanPF6AxPuOw/uWYRKgS5CiBtZi/Yinidny2p9Rs39zw/buJGCnAoGBALII\nwEid0YkyWaSBO7vky1uSkFsTV1eB9DOF2JnufLi46YLQr4c5x+SFA/3GTqKx/+nB\n4nGJdxSpVcawGtLmQUKz01ACJ0Ms2MSyd1ojP8kCF5BQkfCKHO/VZCj2krJmlKGL\nTpk+JH58ToVam1s2N275zthgGMwlUK3CAOU26bb7AoGAO/6zSGRHaiMTpDgz8vhE\n2HaPD2FtWdSvMnBEZA0G7MR43S3cGwaAfzj1mU1osggMnKF6uHgE4nhCs17LuN6B\nMXkWrAWZXvfoUcGqngAzLvcKq3Z1/UPd9wD/FPN2mCd6IajWlTcAhVOjLxWc2m/T\n5sTRqr6+EJsrWPhkUnRCEUQ=\n-----END PRIVATE KEY-----\n",
  "untrustedCert": "-----BEGIN CERTIFICATE-----\nMIICsDCCAZgCCQDQcLsSpADYpjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9N\nYWxpY2lvdXMtQWdlbnQwHhcNMjYxMTA0MTQwMTIxWhcNMzYxMTAxMTQwMTIxWjAa\nMRgwFgYDVQQDDA9NYWxpY2lvdXMtQWdlbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IB\nDwAwggEKAoIBAQC3Ebhpmd7xBY7AimgC+jxUfMB4pID92gbly6O/VQJYaTujXbMB\npN/jKiPiFUNCrebc2K2Jv5YYcywCpm7rHwMTUE1eE+JwaNo3NJg3hWEBSKi5FLVb\nUpmt9YU919GWc8L73pBbWhhppDt/IU3R9RCUoMdhcVqMu37fOwbmzqUvkrCJOd2S\nSkIjEUFkXpwI2IntrKrXTnp+XgnF68t2mK8gA87PHUuZasFpLityZGoFMjtDyqnv\nOLsxpresiy9AZ+NT8Yx2bD9SY74qK0hF2dB1LFrj1KR0eO8mhJJPxF0yI/JAeJU/\nE6NcyoJCa3p2imxA4/vM16H9ZpBIPdJrpzWHAgMBAAEwDQYJKoZIhvcNAQELBQAD\nggEBAAUnuAS2vPxQXg5qgYi422qHzee1OMUHh6E3narG/tHiqdnqNrLQdTrbJOhm\nWg9MQDlXPK0PnhUqkpy3gM3rStIntYhNRCeXs2TRrJVDzrd87WQUHl5pReyXuWIa\n0N8O5IHYfTMD9Cx/kgh3hS0xJ9zFlxSyNBe5RhG0+V1qSiLL0Q2B7FNXxut659TI\nnhmKpwX9EyWO/G8JlsO1EKzpudpOkNWxdLWqgAinVnS9fAomWNoghaZUeUhMagem\nrlu6cFnxXCIqLEEnoN1iw2GJFd6vUcsDYDsvI+QSh6mSxNGN+DVkRPQJj3XeQhly\nz+2cUpfBC1Y06sqpTGTpIscXVqk=\n-----END CERTIFICATE-----\n",
  "untrustedKey": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3Ebhpmd7xBY7A\nimgC+jxUfMB4pID92gbly6O/VQJYaTujXbMBpN/jKiPiFUNCrebc2K2Jv5YYcywC\npm7rHwMTUE1eE+JwaNo3NJg3hWEBSKi5FLVbUpmt9YU919GWc8L73pBbWhhppDt/\nIU3R9RCUoMdhcVqMu37fOwbmzqUvkrCJOd2SSkIjEUFkXpwI2IntrKrXTnp+XgnF\n68t2mK8gA87PHUuZasFpLityZGoFMjtDyqnvOLsxpresiy9AZ+NT8Yx2bD9SY74q\nK0hF2dB1LFrj1KR0eO8mhJJPxF0yI/JAeJU/E6NcyoJCa3p2imxA4/vM16H9ZpBI\nPdJrpzWHAgMBAAECggEAG28HYKPTWfEIRGg5UADp24taWHnmbqQmlnce0cROdqtG\naaPX+G4ZsvQUroObMbnXt86sqtDQEFfqB3ejdY6PKmzFO0zliQzdbppuGRvevo+B\n4UJuLwJAz2XUksDtwosUdCQVI+trbyFSXSnDfKwp0OwLFNokxKQwTgmNbjcXX/pt\ngemNAF0V7gGkMAixOhuAv7+L9tKeQ8B0+qWzgDSmDNZIM5Sq2ocQq7Odw6PXfbfe\ncQkSfIqrHvh/EOfLWMEC5Mf2LJW0F0SAOsUt88MObnbQR3Dpn25Wh9ElHwVq4Nf/\nX1m2MiZHwjHfa+Q4237OWgOiuPaxDP+kyPI9eqRkyQKBgQDmWbBsLvYd706PSw4X\nVhInBuL5MM096ihckap1gLcWK8CELXAYqEuCcjdLJ/XRi9PI7/q++T3X3hkny65n\nAxccgrWah7JiWzLay38bzrfewDae8UnvqFxpGiEF+9VRjHmMMLI7Ha4sZ7sCbI4+\nwo0AdSlBgn8PCCB0oz9IrDfchQKBgQDLdD81H9Bd/Urjeju13Xqj+7YtdQPn+7OI\neTxaa5gVQMkkeUAtW8nmFW3A87f+5rV6kSIrnbbqRP3hy5HVi5WMqwzlYVgR2v9f\n71uH6JL9bFupRvDBWjo9lEhPZ+mtq5YCS7Mgct47zL7BS3W6tPaRzjts4hGe05Pl\ndnb7D/U9mwKBgQDA7oAIrHCxc909wWRlAU8k5uy2QDy3TedOWScHUa6HYE/XpWMN\nE/Biqp1LUoXeY5oX44AF8iXtJvW00jEZ0InL9GJ8sokjPjVi8ixdMw/n/uAA0iHW\nHBKCaUMdiucJbXnkhGjTgLGAOcV1a0zcngCRUJAkcVNQWMMuTgjUKoKDLQKBgAFc\nF4gNXGEkbjmy+W8vucAa0I7hN1N3lS2WUdbw3SVXN4Ds5obnFCRbhE5D0rj7Zb8Z\n9TaBaVWLfH7j02ev9SHpir6Ftgb4hbhoax4vabwT21D4TmecaMM8mHcfZKpqeSgu\nxVW0LtQLfELidDj5OKSk0jTaFfAPze88qXLoGmV9AoGBAIFwZi65V9FKRKduiejp\nc0fmTZo1Bs7bgFfjCyM4XHDFjsnnhdp1NEWjllSGyAVu+5LBLwABDBsM5FswDRYT\nMYUItiouesJg9vDNb8+XDPOHXC7aJdjG1vVcC6k/VXCaxtFH1vUrleS6YGbk8RcC\nsDcv35EmscRR+ezcqw+kU67U\n-----END PRIVATE KEY-----\n"
};

/**
 * MtlsServer provides a mutual TLS server that strictly verifies client certificates
 * and dispatches JSON-RPC payloads over encrypted streams.
 */
class MtlsServer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.key = options.key || TEST_CERTS.serverKey;
    this.cert = options.cert || TEST_CERTS.serverCert;
    this.ca = options.ca || TEST_CERTS.caCert;
    this.requireClientCert = options.requireClientCert !== false;
    this.handler = options.handler || null; // function(jsonRpcRequest, clientInfo): Promise<jsonRpcResponse>
    this.server = null;
    this.port = null;
  }

  async start(port = 0) {
    return new Promise((resolve, reject) => {
      const tlsOptions = {
        key: this.key,
        cert: this.cert,
        ca: this.ca,
        requestCert: true,
        rejectUnauthorized: false // Handled manually to return explicit -32008 JSON-RPC / HTTP errors
      };

      this.server = tls.createServer(tlsOptions, (socket) => {
        this._handleSocket(socket);
      });

      this.server.on('error', (err) => {
        this.emit('error', err);
        reject(err);
      });

      this.server.listen(port, '127.0.0.1', () => {
        const addr = this.server.address();
        this.port = typeof addr === 'object' ? addr.port : port;
        this.emit('listening', { port: this.port });
        resolve({ port: this.port });
      });
    });
  }

  _handleSocket(socket) {
    const cert = socket.getPeerCertificate();
    const isAuthorized = socket.authorized;

    if (this.requireClientCert && (!cert || Object.keys(cert).length === 0 || !isAuthorized)) {
      const clientInfo = {
        authorized: false,
        authorizationError: socket.authorizationError,
        subject: cert && cert.subject ? cert.subject.CN : 'unknown'
      };
      this.emit('unauthorizedClient', clientInfo);

      // Write explicit JSON-RPC error frame and tear down socket
      const errResponse = JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: {
          code: ERROR_CODES.AEGIS_MTLS_UNAUTHORIZED,
          message: `Mutual TLS Authentication Failed: ${socket.authorizationError || 'Valid client certificate required'}`
        }
      }) + '\n';

      socket.write(errResponse, () => {
        socket.destroy();
      });
      return;
    }

    const clientInfo = {
      authorized: true,
      subject: cert.subject ? cert.subject.CN : 'anonymous',
      fingerprint: cert.fingerprint256 || cert.fingerprint
    };
    this.emit('authorizedClient', clientInfo);

    let buffer = '';
    socket.on('data', async (chunk) => {
      buffer += chunk.toString('utf8');
      let newlineIdx;
      while ((newlineIdx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);
        if (line) {
          await this._processLine(socket, line, clientInfo);
        }
      }
    });

    socket.on('error', (err) => {
      this.emit('socketError', err);
    });
  }

  async _processLine(socket, line, clientInfo) {
    try {
      const parsed = JSON.parse(line);
      let response;
      if (this.handler) {
        response = await this.handler(parsed, clientInfo);
      } else {
        response = {
          jsonrpc: '2.0',
          id: parsed.id !== undefined ? parsed.id : null,
          result: { status: 'acknowledged', peer: clientInfo.subject }
        };
      }
      if (response && socket.writable) {
        socket.write(JSON.stringify(response) + '\n');
      }
    } catch (parseErr) {
      if (socket.writable) {
        socket.write(JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error: ' + parseErr.message }
        }) + '\n');
      }
    }
  }

  async stop() {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => {
        this.emit('close');
        resolve();
      });
    });
  }
}

/**
 * MtlsClient connects to an MtlsServer using mutual TLS certificates
 * and provides request/response dispatching.
 */
class MtlsClient {
  constructor(options = {}) {
    this.key = options.key || TEST_CERTS.clientKey;
    this.cert = options.cert || TEST_CERTS.clientCert;
    this.ca = options.ca || TEST_CERTS.caCert;
    this.host = options.host || '127.0.0.1';
    this.port = options.port;
    this.checkServerIdentity = options.checkServerIdentity !== false;
    this.socket = null;
    this.connected = false;
    this.pendingRequests = new Map();
    this.buffer = '';
    this.nextId = 1;
  }

  async connect() {
    return new Promise((resolve, reject) => {
      const options = {
        host: this.host,
        port: this.port,
        key: this.key,
        cert: this.cert,
        ca: this.ca,
        servername: 'localhost',
        rejectUnauthorized: true
      };

      if (!this.checkServerIdentity) {
        options.checkServerIdentity = () => undefined;
      }

      this.socket = tls.connect(options, () => {
        this.connected = true;
        resolve({ authorized: this.socket.authorized, peer: this.socket.getPeerCertificate() });
      });

      this.socket.on('data', (chunk) => {
        this.buffer += chunk.toString('utf8');
        let newlineIdx;
        while ((newlineIdx = this.buffer.indexOf('\n')) !== -1) {
          const line = this.buffer.slice(0, newlineIdx).trim();
          this.buffer = this.buffer.slice(newlineIdx + 1);
          if (line) {
            this._handleResponse(line);
          }
        }
      });

      this.socket.on('error', (err) => {
        this.connected = false;
        reject(err);
      });

      this.socket.on('close', () => {
        this.connected = false;
        for (const [id, req] of this.pendingRequests.entries()) {
          req.reject(new Error('mTLS connection closed'));
          this.pendingRequests.delete(id);
        }
      });
    });
  }

  _handleResponse(line) {
    try {
      const msg = JSON.parse(line);
      const reqId = msg.id;
      if (reqId !== undefined && this.pendingRequests.has(reqId)) {
        const { resolve, reject } = this.pendingRequests.get(reqId);
        this.pendingRequests.delete(reqId);
        if (msg.error) {
          const err = new Error(msg.error.message || 'JSON-RPC Error');
          err.code = msg.error.code;
          err.data = msg.error.data;
          reject(err);
        } else {
          resolve(msg.result);
        }
      }
    } catch (_) {}
  }

  async request(method, params = {}) {
    if (!this.connected || !this.socket || !this.socket.writable) {
      throw new Error('mTLS client not connected');
    }
    const id = this.nextId++;
    const payload = JSON.stringify({
      jsonrpc: '2.0',
      id,
      method,
      params
    }) + '\n';

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });
      this.socket.write(payload);
    });
  }

  close() {
    if (this.socket) {
      this.socket.destroy();
      this.connected = false;
    }
  }
}

module.exports = {
  MtlsServer,
  MtlsClient,
  TEST_CERTS,
  ERROR_CODES
};
