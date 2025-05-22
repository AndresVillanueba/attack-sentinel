#!/usr/bin/env python3
import shodan

API_KEY_SHODAN = '4OIS6fFt5l8jSIsBxuZ5mWnOn9SPWDRf'

cliente_shodan = shodan.Shodan(API_KEY_SHODAN)

def buscar_dispositivos(consulta):

    try:
        resultados = cliente_shodan.search(consulta)
        print(f"Consulta: {consulta}")
        print(f"Resultados encontrados: {resultados['total']}")
        for dispositivo in resultados['matches']:
            ip = dispositivo.get('ip_str', 'N/A')
            banner = dispositivo.get('data', '')
            print(f"IP: {ip}")
            print(f"Banner: {banner}\n{'-' * 50}")
    except shodan.APIError as error:
        print(f"Error en la consulta '{consulta}': {error}")

def main():
   
    buscar_dispositivos('country:"US" OR country:"ES"')
    
    buscar_dispositivos('apache')

if __name__ == '__main__':
    main()
