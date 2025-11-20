<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        // First, make user_id nullable to avoid foreign key constraint issues
        Schema::table('login_logs', function (Blueprint $table) {
            $table->unsignedBigInteger('user_id')->nullable()->change();
        });

        // Rename the typo column: emaiil -> email (if column exists)
        if (Schema::hasColumn('login_logs', 'emaiil')) {
            DB::statement('ALTER TABLE login_logs CHANGE COLUMN emaiil email VARCHAR(255) NULL');
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        // Revert column name back to typo
        if (Schema::hasColumn('login_logs', 'email')) {
            DB::statement('ALTER TABLE login_logs CHANGE COLUMN email emaiil VARCHAR(255) NULL');
        }

        // Revert user_id to not nullable (if needed)
        Schema::table('login_logs', function (Blueprint $table) {
            $table->unsignedBigInteger('user_id')->nullable(false)->change();
        });
    }
};
