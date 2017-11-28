<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Mon coffre fort</title>
  <link rel="stylesheet" href="./css/style.css">
</head>

<body>
<h1> Connexion à mon espace </h1>
<div>
  <form action="./traitement/log.php" method="post">
    <label for="id">Identifiant</label>
    <input type="text" id="id" name="id" placeholder="Identifiant..">

    <label for="mdp">Mot de passe</label>
    <input type="text" id="mdp" name="mdp" placeholder="Votre mot de passe..">

    <input type="submit" value="Ok">
  </form>
</div>

</body>

<footer>
<p>Crée par COLICCHIO Alexandre, GASSER Thibaud, LETAIF Philippe, CHABALIER Andy - ENSISA 2017/2018</p>
</footer>

</html>