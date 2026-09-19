from pe import PE32Class

def main():
    print("Переводчик pe32Plus в Elf64")
    pe = PE32Class()
    i = input("Введите названия файла: ")

    if pe.verifySigDOS(i):
        print("Это DOS, проверяю дальше")

    if not pe.checkSizeFile(i):
        print("Ошибка: Вес файла слишком маленький (меньше 64 байт).")
        return

    offset_signature = pe.verifySigPlus(i)

    if offset_signature["status"]:
        print("Успех!")
        file_info = offset_signature["data"]
        print(f"Тип файла: {file_info['type']}")
        print(f"Смещение Optional Header: {file_info['optional_header_offset']}")
    else:
        print(f"Проверка не пройдена. Причина: {offset_signature['data']}")
        return 




        

if __name__ == "__main__":
    main()