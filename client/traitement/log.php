<?php


	if (empty($_POST['id']) || empty($_POST['mdp'])) {
        
		echo"<script language=\"javascript\">" ; 
		echo"alert('Vous devez remplir tous les champs pour pouvoir vous connecter')";
		echo"document.location.href = '../client.php';"
		echo"</script>";

    }


?>