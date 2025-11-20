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
        Schema::table('quizzes', function (Blueprint $table) {
            $table->unsignedBigInteger('class_room_id')->nullable()->after('user_id');
            $table->boolean('is_class_mode')->default(false)->after('class_room_id');
            
            $table->foreign('class_room_id')->references('id')->on('class_rooms')->onDelete('set null');
            $table->index('class_room_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('quizzes', function (Blueprint $table) {
            $table->dropForeign(['class_room_id']);
            $table->dropIndex(['class_room_id']);
            $table->dropColumn(['class_room_id', 'is_class_mode']);
        });
    }
};
