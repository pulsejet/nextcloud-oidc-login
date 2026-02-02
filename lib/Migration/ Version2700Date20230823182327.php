<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\Migration;

use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version2700Date20230823182327 extends SimpleMigrationStep
{
    /**
     * @param \Closure $schemaClosure The `\Closure` returns a `ISchemaWrapper`
     *
     * @return null|ISchemaWrapper
     */
    private const TABLE_NAME = 'oidc_refresh_tokens';

    public function changeSchema(IOutput $output, \Closure $schemaClosure, array $options)
    {
        /** @var ISchemaWrapper $schema */
        $schema = $schemaClosure();

        if (!$schema->hasTable(self::TABLE_NAME)) {
            $table = $schema->createTable(self::TABLE_NAME);

            $table->addColumn(
                'user_id',
                'string',
                [
                    'notnull' => true,
                ]
            );

            $table->addColumn(
                'token',
                'text',
                [
                    'notnull' => true,
                ]
            );

            $table->setPrimaryKey(['user_id']);
        }

        return $schema;
    }
}
