# HiddenIP

Scanner de sub-rede com interface gráfica (Python + Tkinter) para descobrir e
inventariar os dispositivos da sua rede local.

## Recursos

- Varredura paralela de uma faixa inteira (até /20), com número de threads ajustável
- Detecção de hosts por ICMP, TCP e tabela ARP (acha até quem bloqueia ping)
- MAC, fabricante (OUI) e hostname de cada dispositivo
- Escaneamento de portas TCP com perfis Rápido, Comum e Personalizado
- Identificação de serviços e captura de banners (SSH, FTP, HTTP, etc.)
- Alertas visuais para portas arriscadas expostas
- Tela de detalhes por host, menu de contexto e exportação para CSV

## Instalação

    pip install -r requirements.txt
    python hiddenip.py

No Linux e no macOS, o ping pode exigir `sudo`. No Windows, rode como
administrador se o ICMP falhar.

## Dependências

- Python 3.9 ou superior
- [ping3](https://pypi.org/project/ping3/)
- Opcional: `mac-vendor-lookup` ou um arquivo `oui.txt` na mesma pasta, para
  reconhecer mais fabricantes

## Como usar

1. Digite o IP ou a faixa (`192.168.0.0/24`) e escolha o perfil de portas.
2. Clique em **START SCAN**.
3. Dê duplo clique em um host para ver os detalhes, ou use o botão direito.
4. Exporte o resultado com **EXPORTAR CSV**.

## Aviso legal

Use apenas em redes suas ou com autorização de quem as administra.
O autor não se responsabiliza pelo uso indevido da ferramenta.
