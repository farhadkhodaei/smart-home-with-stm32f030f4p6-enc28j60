/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  ** This notice applies to any and all portions of this file
  * that are not between comment pairs USER CODE BEGIN and
  * USER CODE END. Other portions of this file, whether 
  * inserted by the user or by software development tools
  * are owned by their respective copyright owners.
  *
  * COPYRIGHT(c) 2018 STMicroelectronics
  *
  * Redistribution and use in source and binary forms, with or without modification,
  * are permitted provided that the following conditions are met:
  *   1. Redistributions of source code must retain the above copyright notice,
  *      this list of conditions and the following disclaimer.
  *   2. Redistributions in binary form must reproduce the above copyright notice,
  *      this list of conditions and the following disclaimer in the documentation
  *      and/or other materials provided with the distribution.
  *   3. Neither the name of STMicroelectronics nor the names of its contributors
  *      may be used to endorse or promote products derived from this software
  *      without specific prior written permission.
  *
  * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "network.h"
#include "enc28j60.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
SPI_HandleTypeDef hspi1;

/* USER CODE BEGIN PV */
/* Private variables ---------------------------------------------------------*/
#define PSTRV(s) ((char *)(s))
static uint8_t mymac[6] = {0x62,0x5F,0x70,0x72,0x61,0x79};
static uint8_t myip[4] = {192,168,1,234};
static uint16_t mywwwport = 80;

#define BUFFER_SIZE 1500
uint8_t buf[BUFFER_SIZE+1],browser;
uint16_t plen; 
char * ptr,*chr,chr2[20];
int b1,b2,iii,ij;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_SPI1_Init(void);
/* USER CODE BEGIN PFP */
/* Private function prototypes -----------------------------------------------*/
void sendpage(void);
void testpage(void);
uint16_t make_tcp_data_pos_var(uint8_t *buf,uint16_t pos, char *progmem_s);
void delay_us(int dly);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */
  uint16_t dat_p;
  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_SPI1_Init();
  /* USER CODE BEGIN 2 */
    delay_us(50);
    GPIOA->ODR &= ~(1<<10);
	  delay_us(50);
    GPIOA->ODR |= (1<<10);
	  delay_us(50);
    ENC28J60_Init(mymac);
		GPIOA->ODR |= 1<<4;
    ENC28J60_ClkOut(2);
    delay_us(50);
    ENC28J60_PhyWrite(PHLCON,0x0476);
    delay_us(50);
    init_network(mymac,myip,mywwwport);
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
	plen = ENC28J60_PacketReceive(BUFFER_SIZE,buf);
        if(plen==0) continue;
        if(eth_is_arp(buf,plen)) {
            arp_reply(buf);
            continue;
        }
        if(eth_is_ip(buf,plen)==0) continue;
        if(buf[IP_PROTO]==IP_ICMP && buf[ICMP_TYPE]==ICMP_REQUEST) {
            icmp_reply(buf,plen);
            continue;
        }
        if(buf[IP_PROTO]==IP_TCP && buf[TCP_DST_PORT]==0 && buf[TCP_DST_PORT+1]==mywwwport) {
            if(buf[TCP_FLAGS] & TCP_SYN) {
                tcp_synack(buf);
                continue;
            }
            if(buf[TCP_FLAGS] & TCP_ACK) {
                init_len_info(buf);
                dat_p = get_tcp_data_ptr();
                if(dat_p==0) {
                    if(buf[TCP_FLAGS] & TCP_FIN) tcp_ack(buf);
                    continue;
                }
                
                if(strstr((char*)&(buf[dat_p]),"User Agent")) browser=0;
                else if(strstr((char*)&(buf[dat_p]),"MSIE")) browser=1;
                else browser=2;
                
                if(strncmp("/page",(char*)&(buf[dat_p+4]),5)==0){
                    ptr = (char*)&(buf[dat_p+4]);
                    testpage();
                    sendpage();
                    continue;
                }
            }
        }    
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /**Initializes the CPU, AHB and APB busses clocks 
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }
  /**Initializes the CPU, AHB and APB busses clocks 
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSE;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief SPI1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_SPI1_Init(void)
{

  /* USER CODE BEGIN SPI1_Init 0 */

  /* USER CODE END SPI1_Init 0 */

  /* USER CODE BEGIN SPI1_Init 1 */

  /* USER CODE END SPI1_Init 1 */
  /* SPI1 parameter configuration*/
  hspi1.Instance = SPI1;
  hspi1.Init.Mode = SPI_MODE_MASTER;
  hspi1.Init.Direction = SPI_DIRECTION_2LINES;
  hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi1.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi1.Init.NSS = SPI_NSS_SOFT;
  hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_8;
  hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi1.Init.CRCPolynomial = 7;
  hspi1.Init.CRCLength = SPI_CRC_LENGTH_DATASIZE;
  hspi1.Init.NSSPMode = SPI_NSS_PULSE_ENABLE;
  if (HAL_SPI_Init(&hspi1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN SPI1_Init 2 */

  /* USER CODE END SPI1_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOF_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_3|GPIO_PIN_4|GPIO_PIN_9|GPIO_PIN_10, GPIO_PIN_RESET);

  /*Configure GPIO pins : PA3 PA4 PA9 PA10 */
  GPIO_InitStruct.Pin = GPIO_PIN_3|GPIO_PIN_4|GPIO_PIN_9|GPIO_PIN_10;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

}

/* USER CODE BEGIN 4 */
uint16_t make_tcp_data_pos_var(uint8_t *buf,uint16_t pos, char *progmem_s) {
    char c;
    while((c = *(progmem_s++))) {
        buf[TCP_CHECKSUM+4+pos] = c;
        pos++;
    }                    
    return(pos);
}
void testpage(void) {
  static  int rn = 0, ix;
	char str[10];
	for(ix=4;(*(ptr+ix))!=0;ix++)
	{
		if(((*(ptr+ix-4))=='o') && ((*(ptr+ix-3))=='n') && ((*(ptr+ix-2))=='=') && ((*(ptr+ix-1))=='0') && ((*(ptr+ix-0))=='1')){GPIOA->ODR &= ~(1<<4);plen=make_tcp_data_pos_var(buf,0,PSTRV("<script>document.location.href=\"/page\"</script>"));return;}
	
		if(((*(ptr+ix-4))=='o') && ((*(ptr+ix-3))=='f') && ((*(ptr+ix-2))=='=') && ((*(ptr+ix-1))=='0') && ((*(ptr+ix-0))=='1')){GPIOA->ODR |= (1<<4);plen=make_tcp_data_pos_var(buf,0,PSTRV("<script>document.location.href=\"/page\"</script>"));return;}
	}
	rn++;
	sprintf(str,"  %d",rn);
	plen=make_tcp_data_pos_var(buf,0,PSTRV("<!doctype html><html>"
	"<head><script>function f(i,th){if(i!=\'\'){if(th.checked)str=\"n=0\"+i;else str=\"f=0\"+i;}else str=\"\";document.location.href=\"/pageo\"+str;}</script><style>#myc{background:blue;padding:30px;}body{font-size:50px;background:blue;color:white;}input{width:150px;-ms-transform:scale(5,5);-webkit-transform:scale(5,5);transform:scale(5,5);margin:30px 5px 0px 10px;}input #but{margin-top:20px;}#butt{margin:20px 0px 150px 150px;}</style></head>"
	"<body>"
	"<div id=\"myc\"><input type=\"checkbox\" onclick=\"f(\'1\',this);\""
	));if(!(GPIOA->ODR & (1<<4))) plen=make_tcp_data_pos_var(buf,plen,PSTRV(" checked "));
	plen=make_tcp_data_pos_var(buf,plen,PSTRV(">LED<br></div><div id=\"butt\"><input type=\"button\" value=\"Refresh\" onclick=\"f(\'\');\">"
	"</div>"
	"<div style=\"background: black; color: white;\">"
	"<h1>"));
	plen=make_tcp_data_pos_var(buf,plen,PSTRV(str));
	plen=make_tcp_data_pos_var(buf,plen,PSTRV("</h1></div>"
	"</body>"
	"</html>"));
    
    
}
void sendpage(void) {
    tcp_ack(buf);
    tcp_ack_with_data(buf,plen);
}
void delay_us(int dly)
{
  int i;
  while(dly--)
  {
    i=2;
    while(i--);
  }
}
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  while(1) 
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(char *file, uint32_t line)
{ 
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
    ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
