<?php

return [
    'document_storage_path' => env('DOCUMENT_STORAGE_PATH', ''),
    'document_max_bytes' => (int) env('DOCUMENT_MAX_BYTES', 5242880),
    'document_allowed_extensions' => array_values(array_filter(array_map(
        static fn (string $extension): string => strtolower(trim($extension)),
        explode(',', (string) env('DOCUMENT_ALLOWED_EXTENSIONS', 'pdf,txt,csv,md'))
    ))),
];
