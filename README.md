Code de test implémentant un CredentialProvider Windows.

A ouvrir/tester/adapter dans visual-studio.

Après tests (avec visual studio et une IA, on arrive à sortir une DLL fonctionnelle assez rapidement qui implémenté un 'Credential Provider') en résumé je retiens :
* L'approche "sans mot de passe" nécessite (si on veut faire quelque chose de pro rééllement) une infrastructure PKI (certificats sur carte) via Smart Card Logon, ce qui est (soit disant) très lourd.
* A noter : Windows exige des credentials complets en une fois ; un CredentialProvider ne peut pas "suspendre" l'authentification pour attendre un badge ou autre
* Pour faire du MFA simplement avec la carte, on peut imaginer que la carte sert de pré-identifiant fort (évite la frappe, sécurise le username), tandis que le mot de passe reste le secret -> workflow natif pour Windows : username+password en une seule fois.
* Et donc pareil, faire du MFA en demandant username+password+otp parait vraiment à portée.
* Pour le push ça parait plus compliqué, car on ne peut pas se permettre d'envoyer une notif suite à la seule saisie du username...
