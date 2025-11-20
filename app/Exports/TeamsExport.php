<?php

namespace App\Exports;

use App\Models\Lobby;
use App\Models\Participants;
use Carbon\Carbon;
use Maatwebsite\Excel\Concerns\FromCollection;
use Maatwebsite\Excel\Concerns\WithHeadings;
use Maatwebsite\Excel\Concerns\WithMapping;
use Maatwebsite\Excel\Concerns\WithStyles;
use Maatwebsite\Excel\Concerns\WithEvents;
use Maatwebsite\Excel\Concerns\ShouldAutoSize;
use Maatwebsite\Excel\Concerns\WithCustomStartCell;
use Maatwebsite\Excel\Events\AfterSheet;
use PhpOffice\PhpSpreadsheet\Worksheet\Worksheet;

class TeamsExport implements FromCollection, WithHeadings, WithMapping, WithStyles, WithEvents, ShouldAutoSize, WithCustomStartCell
{
    private $rankCounter = 0;
    private $lobbyId;
    private $subjecId;
    private $event;

    public function __construct($lobbyId, $subjecId)
    {
        $this->lobbyId = $lobbyId;
        $this->subjecId = $subjecId;
    }

    public function startCell(): string
    {
        return 'A3';
    }

    public function collection()
    {
        $lobby = Lobby::where('id', $this->lobbyId)->first();
        
        if (!$lobby) {
            return collect([]);
        }
        
        $this->event = $lobby->name ?? 'Unknown Event';

        return Participants::where("lobby_code", $lobby->lobby_code)
            ->where("archive", 1)
            ->where("subject_id", $this->subjecId)
            ->orderBy('score', 'desc')
            ->get();
    }

    public function headings(): array
    {
        // Headers will be placed at row 3
        return [
            'Quiz Event',
            'Lobby Code',
            'Rank',
            'Team Name',
            'Team Leader Name',
            'Members Name',
            'Total Score',
            'Date & Time of Quiz',
        ];
    }

    public function map($team): array
    {
        $members = json_decode($team->members, true);
        $memberNames = is_array($members) ? collect($members)->pluck('name')->implode(', ') : ($team->members ?? '');
        $this->rankCounter++;

        return [
            $this->event,
            $team->lobby_code,
            $this->rankCounter,
            $team->team,
            $team->team_leader ?? '',
            $memberNames,
            $team->score ?? "0",
            optional($team->updated_at)->format('m/d/Y g:i A'),
        ];
    }

    public function styles(Worksheet $sheet)
    {
        // Header row styling (A3:H3)
        $sheet->getStyle('A3:H3')->applyFromArray([
            'font' => ['bold' => true, 'color' => ['rgb' => 'FFFFFF']],
            'fill' => ['fillType' => 'solid', 'color' => ['rgb' => '800000']],
            'alignment' => ['horizontal' => 'center', 'vertical' => 'center'],
        ]);

        return [];
    }

    public function registerEvents(): array
    {
        return [
            AfterSheet::class => function (AfterSheet $event) {
                $sheet = $event->sheet->getDelegate();

                // --- Logo in column B (B1) ---
                if (file_exists(public_path('images/school_logo.png'))) {
                    try {
                        $drawing = new \PhpOffice\PhpSpreadsheet\Worksheet\Drawing();
                        $drawing->setPath(public_path('images/school_logo.png'));
                        $drawing->setHeight(50);
                        $drawing->setCoordinates('B1');
                        $drawing->setOffsetX(5);
                        $drawing->setWorksheet($sheet);
                    } catch (\Exception $e) {
                        // Silently fail if logo cannot be added
                    }
                }

                // --- University Name (Row 1) - Merge entire row ---
                $sheet->mergeCells('A1:H1');
                $sheet->setCellValue('A1', 'Polytechnic University of the Philippines Taguig Campus');
                $sheet->getStyle('A1')->getFont()->setItalic(true)->setSize(16);
                $sheet->getStyle('A1')->getAlignment()->setHorizontal('center')->setVertical('center');

                // --- Logo in column H (H1) ---
                if (file_exists(public_path('images/LOGO.png'))) {
                    try {
                        $logo_right = new \PhpOffice\PhpSpreadsheet\Worksheet\Drawing();
                        $logo_right->setPath(public_path('images/LOGO.png'));
                        $logo_right->setHeight(50);
                        $logo_right->setCoordinates('H1');
                        $logo_right->setOffsetX(5);
                        $logo_right->setWorksheet($sheet);
                    } catch (\Exception $e) {
                        // Silently fail if logo cannot be added
                    }
                }

                // --- Report Title (Row 2) - Merge entire row ---
                $sheet->mergeCells('A2:H2');
                $sheet->setCellValue('A2', 'PUP Taguig Computerized Quiz Bee Post-Quiz Summary');
                $sheet->getStyle('A2')->getFont()->setBold(true)->setSize(20);
                $sheet->getStyle('A2')->getAlignment()->setHorizontal('center')->setVertical('center');
                $sheet->getRowDimension(2)->setRowHeight(50); // adjust height to add top/bottom space
                // --- Data Borders ---
                $lastRow = $sheet->getHighestRow();
                $sheet->getStyle("A3:H{$lastRow}")->applyFromArray([
                    'borders' => [
                        'allBorders' => [
                            'borderStyle' => \PhpOffice\PhpSpreadsheet\Style\Border::BORDER_THIN,
                            'color' => ['rgb' => '000000']
                        ]
                    ]
                ]);

                // --- Footer ---
                $footerRow = $lastRow + 2;
                $sheet->mergeCells("A{$footerRow}:H{$footerRow}");
                $sheet->setCellValue("A{$footerRow}", 'Generated by: PUPT Quiz Bee Management System | Date:=  ' . Carbon::now('Asia/Manila')->format('Y-m-d'));
                $sheet->getStyle("A{$footerRow}")->getFont()->setItalic(true)->setSize(11);
                $sheet->getStyle("A{$footerRow}")->getAlignment()->setHorizontal('center');

                // --- Auto column width ---
                foreach (range('A', 'H') as $col) {
                    $sheet->getColumnDimension($col)->setAutoSize(true);
                }

                // --- Row heights ---
                $sheet->getRowDimension('1')->setRowHeight(40);
                $sheet->getRowDimension('2')->setRowHeight(25);
                $sheet->getRowDimension('3')->setRowHeight(25);
            },
        ];
    }
}
