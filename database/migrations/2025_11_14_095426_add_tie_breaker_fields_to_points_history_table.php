<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('points_history', function (Blueprint $table) {
            $table->boolean('is_tie_breaker')->default(false)->after('points');
            $table->enum('tie_breaker_round', ['easy', 'average', 'hard'])->nullable()->after('is_tie_breaker');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('points_history', function (Blueprint $table) {
            $table->dropColumn(['is_tie_breaker', 'tie_breaker_round']);
        });
    }
};
