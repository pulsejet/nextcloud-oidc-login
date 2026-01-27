<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\Db\Mappers;

use OCA\OIDCLogin\Db\Entities\RefreshToken;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\QBMapper;
use OCP\IDBConnection;
use OCP\IUser;

class RefreshTokenMapper extends QBMapper
{
    public const TABLENAME = 'oidc_refresh_tokens';

    public function __construct(IDBConnection $db)
    {
        parent::__construct($db, self::TABLENAME, RefreshToken::class);
    }

    /**
     * Get all signatories of a specific type for an user.
     *
     * @throws DoesNotExistException
     */
    public function getTokenByUser(IUser $user): RefreshToken
    {
        $qb = $this->db->getQueryBuilder();
        $qb->select('*')
            ->from(self::TABLENAME)
            ->where($qb->expr()->eq('user_id', $qb->createNamedParameter($user->getUID())))
        ;

        return $this->findEntity($qb);
    }

    public function deleteTokenForUser(IUser $user): void
    {
        $qb = $this->db->getQueryBuilder();
        $qb->delete(self::TABLENAME)
            ->where($qb->expr()->eq('user_id', $qb->createNamedParameter($user->getUID())))
        ;
        $qb->execute();
    }
}
