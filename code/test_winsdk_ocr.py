import asyncio
import os
import winsdk.windows.graphics.imaging as imaging
import winsdk.windows.media.ocr as ocr
import winsdk.windows.storage as storage

async def ocr_image(path):
    abs_path = os.path.abspath(path)
    file = await storage.StorageFile.get_file_from_path_async(abs_path)
    stream = await file.open_async(storage.FileAccessMode.READ)
    decoder = await imaging.BitmapDecoder.create_async(stream)
    bitmap = await decoder.get_software_bitmap_async()
    
    engine = ocr.OcrEngine.try_create_from_user_profile_languages()
    result = await engine.recognize_async(bitmap)
    return result.text

async def main():
    text = await ocr_image("dataset/evidence/images/marketing_profile_console.png")
    print("Recognized text length:", len(text))
    print("First 300 chars:")
    print(text[:300])

asyncio.run(main())
