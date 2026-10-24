import asyncio
import os
import glob
import json
import winsdk.windows.graphics.imaging as imaging
import winsdk.windows.media.ocr as ocr
import winsdk.windows.storage as storage

async def ocr_image(path, engine):
    abs_path = os.path.abspath(path)
    file = await storage.StorageFile.get_file_from_path_async(abs_path)
    stream = await file.open_async(storage.FileAccessMode.READ)
    decoder = await imaging.BitmapDecoder.create_async(stream)
    bitmap = await decoder.get_software_bitmap_async()
    result = await engine.recognize_async(bitmap)
    return result.text

async def main():
    engine = ocr.OcrEngine.try_create_from_user_profile_languages()
    ocr_results = {}
    
    image_files = sorted(glob.glob("dataset/evidence/images/*.png"))
    for img_path in image_files:
        norm_path = img_path.replace('\\', '/')
        print(f"OCRing {norm_path}...")
        text = await ocr_image(img_path, engine)
        ocr_results[norm_path] = text
        print(f"  Done ({len(text)} chars)")
        
    out_file = "dataset/evidence/images_ocr.json"
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(ocr_results, f, indent=2, ensure_ascii=False)
    print(f"Saved OCR results for {len(ocr_results)} images to {out_file}")

if __name__ == '__main__':
    asyncio.run(main())
