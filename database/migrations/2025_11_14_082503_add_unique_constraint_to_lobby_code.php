<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     * Add unique constraint to lobby_code to prevent conflicts when multiple organizers create lobbies
     */
    public function up(): void
    {
        Schema::table('lobby', function (Blueprint $table) {
            // Add unique constraint to lobby_code
            // This ensures that each lobby code is globally unique across all organizers
            // Preventing conflicts when participants join by code
            $table->unique('lobby_code', 'unique_lobby_code');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('lobby', function (Blueprint $table) {
            $table->dropUnique('unique_lobby_code');
        });
    }
};
