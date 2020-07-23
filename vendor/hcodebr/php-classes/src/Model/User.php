<?php

namespace Hcode\Model;

use \Hcode\DB\Sql;
use \Hcode\Mailer;
use \Hcode\Model;

class User extends Model
{

    const SESSION = "User";
    const SECRET = "HcodePhp7_Secret";
    const SECRET_IV = "HcodePhp7_Secret_IV";
    const ERROR = "UserError";
    const ERROR_REGISTER = "UserErrorRegister";
    const SUCCESS = "UserSuccess";
    

    protected $fields = [
        "iduser", "idperson", "deslogin", "despassword", "desemail",
        "nrphone", "inadmin", "dtregister", "desperson"
    ];

    public static function getFromSession()
    {

        $user = new User();

        if (isset($_SESSION[User::SESSION]) && (int)$_SESSION[User::SESSION]['iduser'] > 0) {

            $user->setData($_SESSION[User::SESSION]);
        }

        return $user;
    }

    public static function checkLogin($inadmin = true)
    {

        if (
            !isset($_SESSION[User::SESSION])
            ||
            !$_SESSION[User::SESSION]
            ||
            !(int)$_SESSION[User::SESSION]["iduser"] > 0
        ) {
            //Não está logado
            return false;
        } else {

            if ($inadmin === true && (bool)$_SESSION[User::SESSION]['inadmin'] === true) {

                return true;

            } else if ($inadmin === false) {

                return true;

            } else {

                return false;
            }
        }
    }


    public static function login($login, $password)
    {

        $sql = new Sql();

        $results = $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b 
                                 ON a.idperson = b.idperson WHERE a.deslogin = :LOGIN", array(
                                     ":LOGIN" => $login
                                     ));

        if (count($results) === 0) {
            throw new \Exception("Usuário inexistente ou senha inválida.");
        }

        $data = $results[0];

        if (password_verify($password, $data["despassword"]) === true) {

            $user = new User();

            $user->setData($data);

            $_SESSION[User::SESSION] = $user->getValues();

            return $user;
        } else {
            throw new \Exception("Usuário inexistente ou senha inválida.");
        }
    }

    public static function verifyLogin($inadmin = true)
	{

		if (!User::checkLogin($inadmin)) {

			if ($inadmin) {
				header("Location: /admin/login");
			} else {
				header("Location: /login");
			}
			exit;

		}

	}

    public static function logout()
    {
        $_SESSION[User::SESSION] = NULL;
    }

    public static function listAll()
    {
        $sql = new Sql;

        return $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b 
                                      USING(idperson) ORDER BY b.desperson");
    }

    public function save()
	{
        $invalidos = array("-", ")", "(", " ", "_");

		$sql = new Sql();

		$result = $sql->select("CALL sp_users_save(:desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array(
			":desperson"=> $this->getdesperson(),
			":deslogin"=>$this->getdeslogin(),
			":despassword"=>User::getPasswordHash($this->getdespassword()),
            ":desemail" => strtolower( $this->getdesemail() ),
            ":nrphone" => str_replace ($invalidos, "", $this->getnrphone()),
			":inadmin"=>$this->getinadmin()
		));

		$this->setData($result);

	}

    public function get($iduser)
	{

		$sql = new Sql();

		$results = $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) WHERE a.iduser = :iduser", array(
			":iduser"=>$iduser
		));

		$data = $results[0];

		$data['desperson'] = $data['desperson'];


		$this->setData($data);

	}

    public function update()
	{

        $invalidos = array("-", ")", "(", " ", "_");

		$sql = new Sql();

		$results = $sql->select("CALL sp_usersupdate_save(:iduser, :desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array(
			":iduser"=>$this->getiduser(),
			":desperson"=> $this->getdesperson(),
			":deslogin"=>$this->getdeslogin(),
			":despassword"=>User::getPasswordHash($this->getdespassword()),
            ":desemail" => strtolower( $this->getdesemail() ),
            ":nrphone" => str_replace ($invalidos, "", $this->getnrphone()),
			":inadmin"=>$this->getinadmin()
		));

		$this->setData($results[0]);		

	}


    public function delete()
    {

        $sql = new Sql();

        $sql->query("CALL sp_users_delete(:iduser)", array(
            ":iduser" => $this->getiduser()
        ));
    }

    public static function getForgot($email, $inadmin = true)
    {
        $sql = new Sql();

        $results = $sql->select(
            "SELECT * FROM tb_persons a INNER JOIN tb_users b 
                                    USING(idperson) WHERE a.desemail = :email",
            array(
                ":email" => $email
            )
        );

        if (count($results) === 0) {
            throw new \Exception("Não foi possível recuperar a senha.");
        } else {
            $data = $results[0];

            $results2 = $sql->select("CALL sp_userspasswordsrecoveries_create(:iduser, :desip)", array(
                ":iduser" => $data["iduser"],
                ":desip" => $_SERVER["REMOTE_ADDR"]
            ));

            if (count($results2) === 0) {
                throw new \Exception("Não foi possível recuperar a senha.");
            } else {
                $dataRecovery = $results2[0];

                $code = openssl_encrypt(
                    $dataRecovery['idrecovery'],
                    'AES-128-CBC',
                    pack("a16", User::SECRET),
                    0,
                    pack("a16", User::SECRET_IV)
                );

                $code = base64_encode($code);

                if ($inadmin === true){

                    $link = "http://meuecommerce.com/admin/forgot/reset?code=$code";

                } else {

                    $link = "http://meuecommerce.com/forgot/reset?code=$code";

                }

                

                $mailer = new Mailer(
                    $data["desemail"],
                    $data["desperson"],
                    "Redefinir Senha da Meu Ecommerce Store",
                    "forgot",
                    array(
                        "name" => $data["desperson"],
                        "link" => $link
                    )
                );

                $mailer->send();

                return $data;
            }
        }
    }

    public static function validForgotDecrypt($code)
    {

        $code = base64_decode($code);

        $idrecovery = openssl_decrypt(
            $code,
            'AES-128-CBC',
            pack("a16", User::SECRET),
            0,
            pack("a16", User::SECRET_IV)
        );

        $sql = new Sql();

        $results = $sql->select(
            "SELECT * FROM tb_userspasswordsrecoveries a 
                                 INNER JOIN tb_users b USING(iduser)
                                 INNER JOIN tb_persons c USING (idperson)
                                 WHERE
                                    a.idrecovery = :idrecovery
                                    AND
                                    a.dtrecovery IS NULL
                                    AND 
                                    DATE_ADD(a.dtregister, INTERVAL 1 HOUR) >= NOW()",
            array(
                ":idrecovery" => $idrecovery
            )
        );

        if (count($results) === 0) {
            throw new \Exception("Não foi possível recuperar a senha.");
        } else {
            return $results[0];
        }
    }

    public static function setForgotUsed($idrecovery)
    {

        $sql = new Sql();

        $sql->query("UPDATE tb_userspasswordsrecoveries SET dtrecovery = NOW()
                     WHERE idrecovery = :idrecovery", array(
            ":idrecovery" => $idrecovery
        ));
    }

    public function setPassword($password)
    {

        $sql = new Sql();

        $sql->query("UPDATE tb_users SET despassword = :password WHERE iduser = :iduser", array(
            ":password" => $password,
            ":iduser" => $this->getiduser()
        ));
    }

    public static function getPasswordHash($password)
    {

        return password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);
    }

    public static function setError($msg)
	{

		$_SESSION[User::ERROR] = $msg;

	}

	public static function getError()
	{

		$msg = (isset($_SESSION[User::ERROR]) && $_SESSION[User::ERROR]) ? $_SESSION[User::ERROR] : '';

		User::clearError();

		return $msg;

	}

	public static function clearError()
	{

		$_SESSION[User::ERROR] = NULL;

    }

    public static function setSuccess($msg)
	{

		$_SESSION[User::SUCCESS] = $msg;

	}

	public static function getSuccess()
	{

		$msg = (isset($_SESSION[User::SUCCESS]) && $_SESSION[User::SUCCESS]) ? $_SESSION[User::SUCCESS] : '';

		User::clearSuccess();

		return $msg;

	}

	public static function clearSuccess()
	{

		$_SESSION[User::SUCCESS] = NULL;

    }

    public static function setErrorRegister($msg)
	{

		$_SESSION[User::ERROR_REGISTER] = $msg;

	}

	public static function getErrorRegister()
	{

		$msg = (isset($_SESSION[User::ERROR_REGISTER]) && $_SESSION[User::ERROR_REGISTER]) ? $_SESSION[User::ERROR_REGISTER] : '';

		User::clearErrorRegister();

		return $msg;

	}

	public static function clearErrorRegister()
	{

		$_SESSION[User::ERROR_REGISTER] = NULL;

    }
    
    public static function checkLoginExist($login)
	{

		$sql = new Sql();

		$results = $sql->select("SELECT * FROM tb_users WHERE deslogin = :deslogin", [
			':deslogin'=>$login
		]);

		return (count($results) > 0);

    }
    
    public function getOrders()
    {

        $sql = new Sql();
        
        $results = $sql->select("SELECT * FROM tb_orders a 
                                 INNER JOIN tb_ordersstatus b USING(idstatus)
                                 INNER JOIN tb_carts c USING(idcart)
                                 INNER JOIN tb_users d ON d.iduser = a.iduser
                                 INNER JOIN tb_addresses e USING(idaddress)
                                 INNER JOIN tb_persons f ON f.idperson = d.idperson
                                 WHERE a.iduser = :iduser
                                 ", [
                                     ':iduser' => $this->getiduser()
                                    ]);
        
        return $results;

    }

}
